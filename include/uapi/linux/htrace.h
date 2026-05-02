/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_HTRACE_H
#define _UAPI_LINUX_HTRACE_H

#define HTRACE_ATTACH		1
#define HTRACE_DETACH		2
#define HTRACE_PEEKDATA		3
#define HTRACE_POKEDATA		4
#define HTRACE_GETREGS		5
#define HTRACE_SETREGS		6
#define HTRACE_CONT		7
#define HTRACE_SINGLESTEP	8
#define HTRACE_KILL		9
#define HTRACE_READMEM		10
#define HTRACE_WRITEMEM		11
#define HTRACE_SET_HW_BP	12
#define HTRACE_DEL_HW_BP	13

struct htrace_iovec {
	__u64 remote_addr;
	__u64 local_buf;
	__u64 len;
};

struct htrace_bp_info {
	__u64 addr;
	__s32 type;
	__s32 len;
	__s32 index;
	__s32 _pad;
};

#endif /* _UAPI_LINUX_HTRACE_H */
