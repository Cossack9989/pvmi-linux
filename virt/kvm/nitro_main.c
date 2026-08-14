// SPDX-License-Identifier: GPL-2.0-only
#include <linux/anon_inodes.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/jiffies.h>
#include <linux/kvm_host.h>
#include <linux/nitro_main.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

extern int create_vcpu_fd(struct kvm_vcpu *vcpu);

#define NITRO_MSR_LSTAR 0xc0000082ULL

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

int __weak kvm_arch_vcpu_nitro_refresh_task_cache(struct kvm_vcpu *vcpu)
{
	return 0;
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
	memset(&kvm->nitro.task_tracking, 0, sizeof(kvm->nitro.task_tracking));
	kvm->nitro.runtime_lstar = 0;
	kvm->nitro.task_tracking_enabled = false;
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
	sema_init(&vcpu->nitro.event_sem, 0);
	spin_lock_init(&vcpu->nitro.event_lock);
	vcpu->nitro.events = kcalloc(NITRO_EVENT_RING_SIZE,
				     sizeof(*vcpu->nitro.events),
				     GFP_KERNEL_ACCOUNT);
	vcpu->nitro.direct_ring = kzalloc(sizeof(*vcpu->nitro.direct_ring),
					  GFP_KERNEL_ACCOUNT);
	vcpu->nitro.event_head = 0;
	vcpu->nitro.event_tail = 0;
	vcpu->nitro.events_dropped = 0;
	vcpu->nitro.syscall_trap_enabled = false;
	vcpu->nitro.task_current_slot = 0;
	vcpu->nitro.task_current_addr = 0;
	vcpu->nitro.task_pid = 0;
	vcpu->nitro.task_tgid = 0;
	memset(vcpu->nitro.task_comm, 0, sizeof(vcpu->nitro.task_comm));
	vcpu->nitro.destroyed = false;
}

void nitro_destroy_vcpu_hook(struct kvm_vcpu *vcpu)
{
	struct pvm_switcher_syscall_ring *direct_ring;
	struct event *events;
	unsigned long flags;

	spin_lock_irqsave(&vcpu->nitro.event_lock, flags);
	vcpu->nitro.destroyed = true;
	vcpu->nitro.event_head = 0;
	vcpu->nitro.event_tail = 0;
	events = vcpu->nitro.events;
	direct_ring = vcpu->nitro.direct_ring;
	vcpu->nitro.events = NULL;
	vcpu->nitro.direct_ring = NULL;
	vcpu->nitro.syscall_trap_enabled = false;
	vcpu->nitro.task_current_slot = 0;
	vcpu->nitro.task_current_addr = 0;
	vcpu->nitro.task_pid = 0;
	vcpu->nitro.task_tgid = 0;
	memset(vcpu->nitro.task_comm, 0, sizeof(vcpu->nitro.task_comm));
	spin_unlock_irqrestore(&vcpu->nitro.event_lock, flags);

	kfree(events);
	kfree(direct_ring);
	up(&vcpu->nitro.event_sem);
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

static void nitro_reset_event_ring(struct kvm_vcpu *vcpu)
{
	unsigned long flags;

	spin_lock_irqsave(&vcpu->nitro.event_lock, flags);
	vcpu->nitro.event_head = 0;
	vcpu->nitro.event_tail = 0;
	if (vcpu->nitro.direct_ring) {
		vcpu->nitro.direct_ring->head = 0;
		vcpu->nitro.direct_ring->tail = 0;
		vcpu->nitro.direct_ring->dropped = 0;
	}
	spin_unlock_irqrestore(&vcpu->nitro.event_lock, flags);

	while (!down_trylock(&vcpu->nitro.event_sem))
		;
}

int nitro_ioctl_set_syscall_trap(struct kvm *kvm, bool enabled)
{
	struct kvm_vcpu *vcpu;
	unsigned long i;

	if (!enabled)
		WRITE_ONCE(kvm->nitro.traps, READ_ONCE(kvm->nitro.traps) & ~NITRO_TRAP_SYSCALL);

	kvm_for_each_vcpu(i, vcpu, kvm) {
		nitro_reset_event_ring(vcpu);
		WRITE_ONCE(vcpu->nitro.syscall_trap_enabled, enabled);
		kvm_arch_vcpu_nitro_set_syscall_trap(vcpu, enabled);

		if (!enabled)
			up(&vcpu->nitro.event_sem);
	}

	if (enabled)
		WRITE_ONCE(kvm->nitro.traps, READ_ONCE(kvm->nitro.traps) | NITRO_TRAP_SYSCALL);

	return 0;
}

int nitro_ioctl_set_task_tracking(struct kvm *kvm,
				  struct nitro_task_tracking *tracking)
{
	struct kvm_vcpu *vcpu;
	unsigned long i;
	u64 current_slot = 0;

	WRITE_ONCE(kvm->nitro.task_tracking_enabled, false);
	if (!kvm_arch_nitro_pid_catch_enabled()) {
		memset(&kvm->nitro.task_tracking, 0, sizeof(kvm->nitro.task_tracking));
		goto reset_vcpus;
	}

	kvm->nitro.task_tracking = *tracking;
	if (tracking->linked_lstar && tracking->linked_pcpu_hot &&
	    tracking->linked_per_cpu_offset && tracking->linked_per_cpu_start)
		WRITE_ONCE(kvm->nitro.task_tracking_enabled, true);
	current_slot = tracking->linked_pcpu_hot;

reset_vcpus:
	kvm_for_each_vcpu(i, vcpu, kvm) {
		WRITE_ONCE(vcpu->nitro.task_current_slot, current_slot);
		WRITE_ONCE(vcpu->nitro.task_current_addr, 0);
		WRITE_ONCE(vcpu->nitro.task_pid, 0);
		WRITE_ONCE(vcpu->nitro.task_tgid, 0);
		memset(vcpu->nitro.task_comm, 0, sizeof(vcpu->nitro.task_comm));
	}

	return 0;
}

void nitro_fill_task_event(struct kvm_vcpu *vcpu, struct event *event)
{
	event->pid = READ_ONCE(vcpu->nitro.task_pid);
	event->tgid = READ_ONCE(vcpu->nitro.task_tgid);
	memcpy(event->comm, vcpu->nitro.task_comm, sizeof(event->comm));
}

void nitro_refresh_task_cache(struct kvm_vcpu *vcpu)
{
	if (!READ_ONCE(vcpu->kvm->nitro.task_tracking_enabled))
		return;

	kvm_arch_vcpu_nitro_refresh_task_cache(vcpu);
}
EXPORT_SYMBOL_GPL(nitro_refresh_task_cache);

static bool nitro_try_direct_event(struct kvm_vcpu *vcpu, struct event *event)
{
	struct pvm_switcher_syscall_ring *ring;
	struct pvm_switcher_syscall_event direct;
	u32 tail, head;

	ring = vcpu->nitro.direct_ring;
	if (!ring)
		return false;

	tail = READ_ONCE(ring->tail);
	head = READ_ONCE(ring->head);
	if (head == tail)
		return false;

	direct = ring->events[tail];
	WRITE_ONCE(ring->tail, (tail + 1) % PVM_SWITCHER_SYSCALL_RING_SIZE);

	event->present = 1;
	event->direction = ENTER;
	event->type = SYSCALL;
	event->pid = direct.pid;
	event->tgid = direct.tgid;
	memcpy(event->comm, direct.comm, sizeof(event->comm));
	event->nr = direct.nr;
	event->args[0] = direct.args[0];
	event->args[1] = direct.args[1];
	event->args[2] = direct.args[2];
	event->args[3] = direct.args[3];
	event->args[4] = direct.args[4];
	event->args[5] = direct.args[5];
	event->regs.rip = direct.rip;

	return true;
}

int nitro_ioctl_get_event(struct kvm_vcpu *vcpu, struct event *event)
{
	unsigned long flags;
	int r;

	memset(event, 0, sizeof(*event));
	if (nitro_try_direct_event(vcpu, event))
		return 0;

	r = down_timeout(&vcpu->nitro.event_sem, msecs_to_jiffies(1000));
	if (r)
		return r;

	if (nitro_try_direct_event(vcpu, event))
		return 0;

	spin_lock_irqsave(&vcpu->nitro.event_lock, flags);
	if (vcpu->nitro.event_head != vcpu->nitro.event_tail) {
		*event = vcpu->nitro.events[vcpu->nitro.event_tail];
		vcpu->nitro.event_tail =
			(vcpu->nitro.event_tail + 1) % NITRO_EVENT_RING_SIZE;
	} else if (vcpu->nitro.destroyed) {
		r = -ENODEV;
	} else {
		r = -EAGAIN;
	}
	spin_unlock_irqrestore(&vcpu->nitro.event_lock, flags);

	return r;
}

int nitro_ioctl_continue(struct kvm_vcpu *vcpu)
{
	return 0;
}

static int nitro_ioctl_get_regs(struct kvm_vcpu *vcpu, void __user *argp)
{
	struct kvm_regs *regs;
	int r;

	regs = kzalloc(sizeof(*regs), GFP_KERNEL);
	if (!regs)
		return -ENOMEM;

	if (vcpu->kvm->mm != current->mm)
		r = -EAGAIN;
	else
		r = kvm_arch_vcpu_ioctl_get_regs(vcpu, regs);

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

	if (vcpu->kvm->mm != current->mm)
		r = -EAGAIN;
	else
		r = kvm_arch_vcpu_ioctl_set_regs(vcpu, regs);

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

	if (vcpu->kvm->mm != current->mm)
		r = -EAGAIN;
	else
		r = kvm_arch_vcpu_ioctl_get_sregs(vcpu, sregs);

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

	if (vcpu->kvm->mm != current->mm)
		r = -EAGAIN;
	else
		r = kvm_arch_vcpu_ioctl_set_sregs(vcpu, sregs);

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
	unsigned long flags;
	bool queued = true;
	u32 next;

	if (!nitro_is_trap_set(vcpu->kvm, NITRO_TRAP_SYSCALL))
		return;

	spin_lock_irqsave(&vcpu->nitro.event_lock, flags);
	if (vcpu->nitro.destroyed || !vcpu->nitro.events) {
		spin_unlock_irqrestore(&vcpu->nitro.event_lock, flags);
		return;
	}

	next = (vcpu->nitro.event_head + 1) % NITRO_EVENT_RING_SIZE;
	if (next == vcpu->nitro.event_tail) {
		vcpu->nitro.events_dropped++;
		vcpu->nitro.event_tail =
			(vcpu->nitro.event_tail + 1) % NITRO_EVENT_RING_SIZE;
		queued = false;
	}

	vcpu->nitro.events[vcpu->nitro.event_head] = *event;
	vcpu->nitro.event_head = next;
	spin_unlock_irqrestore(&vcpu->nitro.event_lock, flags);
	if (queued)
		up(&vcpu->nitro.event_sem);
}

void nitro_report_syscall_enter(struct kvm_vcpu *vcpu)
{
	struct event event;

	memset(&event, 0, sizeof(event));
	event.present = 1;
	event.direction = ENTER;
	event.type = SYSCALL;
	nitro_refresh_task_cache(vcpu);
	nitro_fill_task_event(vcpu, &event);
	kvm_arch_vcpu_nitro_get_event(vcpu, &event);
	nitro_fill_syscall_from_regs(&event);

	nitro_report_event(vcpu, &event);
}
EXPORT_SYMBOL_GPL(nitro_report_syscall_enter);

void nitro_report_syscall_exit(struct kvm_vcpu *vcpu)
{
}
EXPORT_SYMBOL_GPL(nitro_report_syscall_exit);

void nitro_report_kaslr(struct kvm_vcpu *vcpu, u64 runtime_entry, u64 source)
{
	struct event event;

	memset(&event, 0, sizeof(event));
	event.present = 1;
	event.direction = ENTER;
	event.type = KASLR;
	event.metadata[0] = runtime_entry;
	event.metadata[1] = source;
	if (source == NITRO_MSR_LSTAR)
		WRITE_ONCE(vcpu->kvm->nitro.runtime_lstar, runtime_entry);

	nitro_report_event(vcpu, &event);
}
EXPORT_SYMBOL_GPL(nitro_report_kaslr);
