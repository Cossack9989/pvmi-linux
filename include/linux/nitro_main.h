/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_NITRO_MAIN_H
#define _LINUX_NITRO_MAIN_H

#include <linux/completion.h>
#include <linux/bits.h>
#include <linux/mutex.h>
#include <linux/nitro.h>
#include <linux/semaphore.h>
#include <linux/types.h>

struct kvm;
struct kvm_vcpu;

#define NITRO_TRAP_SYSCALL	BIT(0)

struct nitro {
	u32 traps;
};

struct nitro_vcpu {
	struct completion continue_completion;
	struct semaphore event_sem;
	struct mutex lock;
	struct event event;
	struct event pending_syscall;
	bool regs_dirty;
	bool sregs_dirty;
	bool syscall_pending;
	bool waiting_for_continue;
	bool destroyed;
};

struct kvm *nitro_get_vm_by_creator(pid_t creator);

int nitro_ioctl_num_vms(void);
int nitro_ioctl_attach_vcpus(struct kvm *kvm, struct nitro_vcpus *nvcpus);

void nitro_create_vm_hook(struct kvm *kvm);
void nitro_destroy_vm_hook(struct kvm *kvm);
void nitro_create_vcpu_hook(struct kvm_vcpu *vcpu);
void nitro_destroy_vcpu_hook(struct kvm_vcpu *vcpu);

int nitro_ioctl_set_syscall_trap(struct kvm *kvm, bool enabled);
int nitro_ioctl_get_event(struct kvm_vcpu *vcpu, struct event *event);
int nitro_ioctl_continue(struct kvm_vcpu *vcpu);
long nitro_vcpu_ioctl(struct kvm_vcpu *vcpu, unsigned int ioctl,
		      unsigned long arg);

bool nitro_is_trap_set(struct kvm *kvm, u32 trap);
void nitro_report_syscall_enter(struct kvm_vcpu *vcpu);
void nitro_report_syscall_exit(struct kvm_vcpu *vcpu);
void kvm_arch_vcpu_nitro_get_event(struct kvm_vcpu *vcpu, struct event *event);
int kvm_arch_vcpu_nitro_set_event(struct kvm_vcpu *vcpu, struct event *event,
				  bool regs_dirty, bool sregs_dirty);

#endif /* _LINUX_NITRO_MAIN_H */
