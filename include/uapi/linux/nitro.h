/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_NITRO_H
#define _UAPI_LINUX_NITRO_H

#include <linux/ioctl.h>
#include <linux/kvm.h>
#include <linux/posix_types.h>
#include <linux/types.h>

#define NITRO_MAX_VCPUS 64

enum syscall_direction {
	ENTER,
	EXIT,
};

enum syscall_type {
	SYSENTER,
	SYSCALL,
	KASLR,
};

struct event {
	__u8 present;
	__u8 pad[3];
	__u32 direction;
	__u32 type;
	__u64 nr;
	__u64 args[6];
	__s64 ret;
	__u64 metadata[4];
	struct kvm_regs regs;
	struct kvm_sregs sregs;
};

struct nitro_vcpus {
	__s32 num_vcpus;
	__s32 ids[NITRO_MAX_VCPUS];
	__s32 fds[NITRO_MAX_VCPUS];
};

#define KVM_NITRO_EVENT_ERROR			1
#define KVM_NITRO_EVENT_SYSCALL			2
#define KVM_NITRO_EVENT_SYSRET			3
#define KVM_NITRO_EVENT_KASLR			4

#define KVM_NITRO_NUM_VMS		_IO(KVMIO, 0xe0)
#define KVM_NITRO_ATTACH_VM		_IOW(KVMIO, 0xe1, __kernel_pid_t)

#define KVM_NITRO_ATTACH_VCPUS		_IOR(KVMIO, 0xe2, struct nitro_vcpus)
#define KVM_NITRO_SET_SYSCALL_TRAP	_IOW(KVMIO, 0xe3, __u8)

#define KVM_NITRO_GET_EVENT		_IOR(KVMIO, 0xe5, struct event)
#define KVM_NITRO_CONTINUE		_IO(KVMIO, 0xe6)

#define KVM_NITRO_GET_REGS		_IOR(KVMIO, 0xe7, struct kvm_regs)
#define KVM_NITRO_SET_REGS		_IOW(KVMIO, 0xe8, struct kvm_regs)
#define KVM_NITRO_GET_SREGS		_IOR(KVMIO, 0xe9, struct kvm_sregs)
#define KVM_NITRO_SET_SREGS		_IOW(KVMIO, 0xea, struct kvm_sregs)

#endif /* _UAPI_LINUX_NITRO_H */
