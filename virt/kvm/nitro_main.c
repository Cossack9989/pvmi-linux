// SPDX-License-Identifier: GPL-2.0-only
#include <linux/anon_inodes.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/jiffies.h>
#include <linux/kvm_host.h>
#include <linux/nitro_main.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

extern int create_vcpu_fd(struct kvm_vcpu *vcpu);

void __weak kvm_arch_vcpu_nitro_get_event(struct kvm_vcpu *vcpu,
					  struct event *event)
{
}

int __weak kvm_arch_vcpu_nitro_set_event(struct kvm_vcpu *vcpu,
					 struct event *event,
					 bool regs_dirty, bool sregs_dirty)
{
	return -EOPNOTSUPP;
}

void __weak kvm_arch_vcpu_nitro_set_syscall_trap(struct kvm_vcpu *vcpu,
						 bool enabled)
{
}

struct kvm *nitro_get_vm_by_creator(pid_t creator)
{
	struct kvm *kvm;

	mutex_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list) {
		if (kvm->userspace_pid == creator) {
			kvm_get_kvm(kvm);
			mutex_unlock(&kvm_lock);
			return kvm;
		}
	}
	mutex_unlock(&kvm_lock);

	return NULL;
}

void nitro_create_vm_hook(struct kvm *kvm)
{
	kvm->nitro.traps = 0;
	kvm->userspace_pid = task_pid_nr(current);
}

void nitro_destroy_vm_hook(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu;
	unsigned long i;

	kvm->nitro.traps = 0;
	kvm_for_each_vcpu(i, vcpu, kvm)
		nitro_destroy_vcpu_hook(vcpu);
}

void nitro_create_vcpu_hook(struct kvm_vcpu *vcpu)
{
	mutex_init(&vcpu->nitro.lock);
	init_completion(&vcpu->nitro.continue_completion);
	sema_init(&vcpu->nitro.event_sem, 0);
	memset(&vcpu->nitro.event, 0, sizeof(vcpu->nitro.event));
	memset(&vcpu->nitro.pending_syscall, 0, sizeof(vcpu->nitro.pending_syscall));
	vcpu->nitro.regs_dirty = false;
	vcpu->nitro.sregs_dirty = false;
	vcpu->nitro.syscall_pending = false;
	vcpu->nitro.waiting_for_continue = false;
	vcpu->nitro.destroyed = false;
}

void nitro_destroy_vcpu_hook(struct kvm_vcpu *vcpu)
{
	mutex_lock(&vcpu->nitro.lock);
	vcpu->nitro.destroyed = true;
	vcpu->nitro.event.present = 0;
	vcpu->nitro.pending_syscall.present = 0;
	vcpu->nitro.regs_dirty = false;
	vcpu->nitro.sregs_dirty = false;
	vcpu->nitro.syscall_pending = false;
	vcpu->nitro.waiting_for_continue = false;
	mutex_unlock(&vcpu->nitro.lock);

	up(&vcpu->nitro.event_sem);
	complete_all(&vcpu->nitro.continue_completion);
}

int nitro_ioctl_num_vms(void)
{
	struct kvm *kvm;
	int count = 0;

	mutex_lock(&kvm_lock);
	list_for_each_entry(kvm, &vm_list, vm_list)
		count++;
	mutex_unlock(&kvm_lock);

	return count;
}

int nitro_ioctl_attach_vcpus(struct kvm *kvm, struct nitro_vcpus *nvcpus)
{
	struct kvm_vcpu *vcpu;
	unsigned long i;
	int r = 0;

	memset(nvcpus, 0, sizeof(*nvcpus));

	mutex_lock(&kvm->lock);
	nvcpus->num_vcpus = atomic_read(&kvm->online_vcpus);
	if (nvcpus->num_vcpus > NITRO_MAX_VCPUS) {
		r = -E2BIG;
		goto out_unlock;
	}

	kvm_for_each_vcpu(i, vcpu, kvm) {
		int fd;

		kvm_get_kvm(kvm);
		fd = create_vcpu_fd(vcpu);
		if (fd < 0) {
			int j;

			kvm_put_kvm_no_destroy(kvm);
			for (j = 0; j < r; j++)
				close_fd(nvcpus->fds[j]);
			r = fd;
			goto out_unlock;
		}

		nvcpus->ids[r] = vcpu->vcpu_id;
		nvcpus->fds[r] = fd;
		r++;
	}

	r = 0;

out_unlock:
	mutex_unlock(&kvm->lock);
	return r;
}

bool nitro_is_trap_set(struct kvm *kvm, u32 trap)
{
	return READ_ONCE(kvm->nitro.traps) & trap;
}

int nitro_ioctl_set_syscall_trap(struct kvm *kvm, bool enabled)
{
	struct kvm_vcpu *vcpu;
	unsigned long i;

	if (enabled)
		WRITE_ONCE(kvm->nitro.traps, READ_ONCE(kvm->nitro.traps) | NITRO_TRAP_SYSCALL);
	else
		WRITE_ONCE(kvm->nitro.traps, READ_ONCE(kvm->nitro.traps) & ~NITRO_TRAP_SYSCALL);

	kvm_for_each_vcpu(i, vcpu, kvm) {
		mutex_lock(&vcpu->nitro.lock);
		vcpu->nitro.event.present = 0;
		vcpu->nitro.pending_syscall.present = 0;
		vcpu->nitro.regs_dirty = false;
		vcpu->nitro.sregs_dirty = false;
		vcpu->nitro.syscall_pending = false;
		vcpu->nitro.waiting_for_continue = false;
		if (enabled)
			reinit_completion(&vcpu->nitro.continue_completion);
		kvm_arch_vcpu_nitro_set_syscall_trap(vcpu, enabled);
		mutex_unlock(&vcpu->nitro.lock);

		if (!enabled) {
			up(&vcpu->nitro.event_sem);
			complete_all(&vcpu->nitro.continue_completion);
		}
	}

	return 0;
}

int nitro_ioctl_get_event(struct kvm_vcpu *vcpu, struct event *event)
{
	int r;

	memset(event, 0, sizeof(*event));
	r = down_timeout(&vcpu->nitro.event_sem, msecs_to_jiffies(1000));
	if (r)
		return r;

	mutex_lock(&vcpu->nitro.lock);
	if (vcpu->nitro.event.present)
		*event = vcpu->nitro.event;
	else if (vcpu->nitro.destroyed)
		r = -ENODEV;
	else
		r = -EAGAIN;
	mutex_unlock(&vcpu->nitro.lock);

	return r;
}

int nitro_ioctl_continue(struct kvm_vcpu *vcpu)
{
	mutex_lock(&vcpu->nitro.lock);
	if (!vcpu->nitro.waiting_for_continue) {
		mutex_unlock(&vcpu->nitro.lock);
		return -EAGAIN;
	}

	vcpu->nitro.waiting_for_continue = false;
	mutex_unlock(&vcpu->nitro.lock);

	complete(&vcpu->nitro.continue_completion);
	return 0;
}

static int nitro_ioctl_get_regs(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct kvm_regs *regs;
	int r;

	regs = kzalloc(sizeof(*regs), GFP_KERNEL);
	if (!regs)
		return -ENOMEM;

	mutex_lock(&vcpu->nitro.lock);
	if (vcpu->nitro.event.present) {
		*regs = vcpu->nitro.event.regs;
		r = 0;
	} else {
		mutex_unlock(&vcpu->nitro.lock);
		if (vcpu->kvm->mm != current->mm)
			r = -EAGAIN;
		else
			r = kvm_arch_vcpu_ioctl_get_regs(vcpu, regs);
		mutex_lock(&vcpu->nitro.lock);
	}
	mutex_unlock(&vcpu->nitro.lock);

	if (!r && copy_to_user(argp, regs, sizeof(*regs)))
		r = -EFAULT;

	kfree(regs);
	return r;
}

static int nitro_ioctl_set_regs(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct kvm_regs *regs;
	int r;

	regs = memdup_user(argp, sizeof(*regs));
	if (IS_ERR(regs))
		return PTR_ERR(regs);

	mutex_lock(&vcpu->nitro.lock);
	if (vcpu->nitro.event.present) {
		vcpu->nitro.event.regs = *regs;
		vcpu->nitro.regs_dirty = true;
		r = 0;
	} else {
		mutex_unlock(&vcpu->nitro.lock);
		if (vcpu->kvm->mm != current->mm)
			r = -EAGAIN;
		else
			r = kvm_arch_vcpu_ioctl_set_regs(vcpu, regs);
		mutex_lock(&vcpu->nitro.lock);
	}
	mutex_unlock(&vcpu->nitro.lock);

	kfree(regs);
	return r;
}

static int nitro_ioctl_get_sregs(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct kvm_sregs *sregs;
	int r;

	sregs = kzalloc(sizeof(*sregs), GFP_KERNEL);
	if (!sregs)
		return -ENOMEM;

	mutex_lock(&vcpu->nitro.lock);
	if (vcpu->nitro.event.present) {
		*sregs = vcpu->nitro.event.sregs;
		r = 0;
	} else {
		mutex_unlock(&vcpu->nitro.lock);
		if (vcpu->kvm->mm != current->mm)
			r = -EAGAIN;
		else
			r = kvm_arch_vcpu_ioctl_get_sregs(vcpu, sregs);
		mutex_lock(&vcpu->nitro.lock);
	}
	mutex_unlock(&vcpu->nitro.lock);

	if (!r && copy_to_user(argp, sregs, sizeof(*sregs)))
		r = -EFAULT;

	kfree(sregs);
	return r;
}

static int nitro_ioctl_set_sregs(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct kvm_sregs *sregs;
	int r;

	sregs = memdup_user(argp, sizeof(*sregs));
	if (IS_ERR(sregs))
		return PTR_ERR(sregs);

	mutex_lock(&vcpu->nitro.lock);
	if (vcpu->nitro.event.present) {
		vcpu->nitro.event.sregs = *sregs;
		vcpu->nitro.sregs_dirty = true;
		r = 0;
	} else {
		mutex_unlock(&vcpu->nitro.lock);
		if (vcpu->kvm->mm != current->mm)
			r = -EAGAIN;
		else
			r = kvm_arch_vcpu_ioctl_set_sregs(vcpu, sregs);
		mutex_lock(&vcpu->nitro.lock);
	}
	mutex_unlock(&vcpu->nitro.lock);

	kfree(sregs);
	return r;
}

long nitro_vcpu_ioctl(struct kvm_vcpu *vcpu, unsigned int ioctl,
		      unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct event *event;
	int r;

	switch (ioctl) {
	case KVM_NITRO_GET_EVENT:
		event = kzalloc(sizeof(*event), GFP_KERNEL);
		if (!event)
			return -ENOMEM;

		r = nitro_ioctl_get_event(vcpu, event);
		if (!r && copy_to_user(argp, event, sizeof(*event)))
			r = -EFAULT;
		kfree(event);
		return r;
	case KVM_NITRO_CONTINUE:
		return nitro_ioctl_continue(vcpu);
	case KVM_NITRO_GET_REGS:
		return nitro_ioctl_get_regs(vcpu, argp);
	case KVM_NITRO_SET_REGS:
		return nitro_ioctl_set_regs(vcpu, argp);
	case KVM_NITRO_GET_SREGS:
		return nitro_ioctl_get_sregs(vcpu, argp);
	case KVM_NITRO_SET_SREGS:
		return nitro_ioctl_set_sregs(vcpu, argp);
	default:
		return -ENOIOCTLCMD;
	}
}

static void nitro_fill_syscall_from_regs(struct event *event)
{
	event->nr = event->regs.rax;
	event->args[0] = event->regs.rdi;
	event->args[1] = event->regs.rsi;
	event->args[2] = event->regs.rdx;
	event->args[3] = event->regs.r10;
	event->args[4] = event->regs.r8;
	event->args[5] = event->regs.r9;
	event->ret = 0;
}

static void nitro_report_event(struct kvm_vcpu *vcpu, struct event *event)
{
	long wait_r;
	int r;

	if (!nitro_is_trap_set(vcpu->kvm, NITRO_TRAP_SYSCALL))
		return;

	mutex_lock(&vcpu->nitro.lock);
	if (vcpu->nitro.destroyed) {
		mutex_unlock(&vcpu->nitro.lock);
		return;
	}

	reinit_completion(&vcpu->nitro.continue_completion);
	vcpu->nitro.event = *event;
	vcpu->nitro.waiting_for_continue = true;
	mutex_unlock(&vcpu->nitro.lock);

	up(&vcpu->nitro.event_sem);
	wait_r = wait_for_completion_interruptible_timeout(
		&vcpu->nitro.continue_completion, msecs_to_jiffies(30000));

	mutex_lock(&vcpu->nitro.lock);
	r = kvm_arch_vcpu_nitro_set_event(vcpu, &vcpu->nitro.event,
					  vcpu->nitro.regs_dirty,
					  vcpu->nitro.sregs_dirty);
	vcpu->nitro.event.present = 0;
	vcpu->nitro.regs_dirty = false;
	vcpu->nitro.sregs_dirty = false;
	vcpu->nitro.waiting_for_continue = false;
	mutex_unlock(&vcpu->nitro.lock);

	if (r)
		pr_warn_ratelimited("nitro: failed to apply event state on vcpu %d: %d\n",
				    vcpu->vcpu_id, r);
	if (!wait_r)
		pr_info_ratelimited("nitro: timed out waiting for continue on vcpu %d\n",
				    vcpu->vcpu_id);
}

void nitro_report_syscall_enter(struct kvm_vcpu *vcpu)
{
	struct event event;

	memset(&event, 0, sizeof(event));
	event.present = 1;
	event.direction = ENTER;
	event.type = SYSCALL;
	kvm_arch_vcpu_nitro_get_event(vcpu, &event);
	nitro_fill_syscall_from_regs(&event);

	mutex_lock(&vcpu->nitro.lock);
	vcpu->nitro.pending_syscall = event;
	vcpu->nitro.syscall_pending = true;
	mutex_unlock(&vcpu->nitro.lock);

	nitro_report_event(vcpu, &event);
}
EXPORT_SYMBOL_GPL(nitro_report_syscall_enter);

void nitro_report_syscall_exit(struct kvm_vcpu *vcpu)
{
	struct event event;

	if (!nitro_is_trap_set(vcpu->kvm, NITRO_TRAP_SYSCALL))
		return;

	mutex_lock(&vcpu->nitro.lock);
	if (!vcpu->nitro.syscall_pending) {
		mutex_unlock(&vcpu->nitro.lock);
		return;
	}
	event = vcpu->nitro.pending_syscall;
	vcpu->nitro.pending_syscall.present = 0;
	vcpu->nitro.syscall_pending = false;
	mutex_unlock(&vcpu->nitro.lock);

	event.present = 1;
	event.direction = EXIT;
	kvm_arch_vcpu_nitro_get_event(vcpu, &event);
	event.ret = (s64)event.regs.rax;

	nitro_report_event(vcpu, &event);
}
EXPORT_SYMBOL_GPL(nitro_report_syscall_exit);
