/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HTRACE_H
#define _LINUX_HTRACE_H

#include <linux/types.h>

struct task_struct;
struct pt_regs;

struct htrace_context;

struct htrace_context *htrace_find_ctx(pid_t pid);
bool htrace_is_target(struct task_struct *task);
void htrace_handle_single_step(struct task_struct *task, struct pt_regs *regs);

#endif /* _LINUX_HTRACE_H */
