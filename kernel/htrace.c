// SPDX-License-Identifier: GPL-2.0
#include <linux/syscalls.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/signal.h>
#include <linux/hw_breakpoint.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/mm.h>
#include <linux/htrace.h>
#include <uapi/linux/htrace.h>
#include <asm/ptrace.h>
#include <asm/processor.h>
#include <asm/debug-monitors.h>

#define HTRACE_MAX_HW_BPS	16
#define HTRACE_HT_BITS		8

static DEFINE_HASHTABLE(htrace_table, HTRACE_HT_BITS);
static DEFINE_SPINLOCK(htrace_lock);

struct htrace_context {
	struct hlist_node node;
	pid_t target_pid;
	pid_t tracer_pid;
	struct task_struct *target;
	struct perf_event *hw_bps[HTRACE_MAX_HW_BPS];
	int num_hw_bps;
	bool single_stepping;
};

struct htrace_context *htrace_find_ctx(pid_t pid)
{
	struct htrace_context *ctx;

	hash_for_each_possible(htrace_table, ctx, node, pid) {
		if (ctx->target_pid == pid)
			return ctx;
	}
	return NULL;
}

bool htrace_is_target(struct task_struct *task)
{
	bool found;
	unsigned long flags;

	spin_lock_irqsave(&htrace_lock, flags);
	found = htrace_find_ctx(task->tgid) != NULL;
	spin_unlock_irqrestore(&htrace_lock, flags);
	return found;
}

void htrace_handle_single_step(struct task_struct *task, struct pt_regs *regs)
{
	struct htrace_context *ctx;
	unsigned long flags;

	user_disable_single_step(task);

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx(task->tgid);
	if (ctx)
		ctx->single_stepping = false;
	spin_unlock_irqrestore(&htrace_lock, flags);

	send_sig(SIGSTOP, task, 1);
}

static void htrace_bp_handler(struct perf_event *bp,
			      struct perf_sample_data *data,
			      struct pt_regs *regs)
{
	send_sig(SIGSTOP, current, 1);
}

static struct htrace_context *htrace_find_ctx_for_tracer(pid_t target_pid,
							 pid_t tracer_pid)
{
	struct htrace_context *ctx;

	hash_for_each_possible(htrace_table, ctx, node, target_pid) {
		if (ctx->target_pid == target_pid &&
		    ctx->tracer_pid == tracer_pid)
			return ctx;
	}
	return NULL;
}

static void htrace_cleanup_bps(struct htrace_context *ctx)
{
	int i;

	for (i = 0; i < HTRACE_MAX_HW_BPS; i++) {
		if (ctx->hw_bps[i]) {
			unregister_hw_breakpoint(ctx->hw_bps[i]);
			ctx->hw_bps[i] = NULL;
		}
	}
	ctx->num_hw_bps = 0;
}

static long htrace_attach(pid_t pid)
{
	struct task_struct *task;
	struct htrace_context *ctx;
	unsigned long flags;

	if (!capable(CAP_SYS_PTRACE))
		return -EPERM;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	if (!task)
		return -ESRCH;

	spin_lock_irqsave(&htrace_lock, flags);
	if (htrace_find_ctx_for_tracer(pid, current->tgid)) {
		spin_unlock_irqrestore(&htrace_lock, flags);
		put_task_struct(task);
		return -EALREADY;
	}
	spin_unlock_irqrestore(&htrace_lock, flags);

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		put_task_struct(task);
		return -ENOMEM;
	}

	ctx->target_pid = pid;
	ctx->tracer_pid = current->tgid;
	ctx->target = task;

	spin_lock_irqsave(&htrace_lock, flags);
	hash_add(htrace_table, &ctx->node, pid);
	spin_unlock_irqrestore(&htrace_lock, flags);

	send_sig(SIGSTOP, task, 1);
	return 0;
}

static long htrace_detach(pid_t pid)
{
	struct htrace_context *ctx;
	struct task_struct *task;
	unsigned long flags;

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx_for_tracer(pid, current->tgid);
	if (!ctx) {
		spin_unlock_irqrestore(&htrace_lock, flags);
		return -ESRCH;
	}
	hash_del(&ctx->node);
	spin_unlock_irqrestore(&htrace_lock, flags);

	task = ctx->target;

	if (ctx->single_stepping)
		user_disable_single_step(task);

	htrace_cleanup_bps(ctx);
	send_sig(SIGCONT, task, 1);
	put_task_struct(task);
	kfree(ctx);
	return 0;
}

static long htrace_peekdata(pid_t pid, unsigned long addr, unsigned long __user *udata)
{
	struct htrace_context *ctx;
	unsigned long flags, val;
	struct task_struct *task;
	int ret;

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx_for_tracer(pid, current->tgid);
	task = ctx ? ctx->target : NULL;
	if (task)
		get_task_struct(task);
	spin_unlock_irqrestore(&htrace_lock, flags);

	if (!task)
		return -ESRCH;

	ret = access_process_vm(task, addr, &val, sizeof(val), FOLL_FORCE);
	put_task_struct(task);

	if (ret != sizeof(val))
		return -EIO;

	return put_user(val, udata);
}

static long htrace_pokedata(pid_t pid, unsigned long addr, unsigned long val)
{
	struct htrace_context *ctx;
	unsigned long flags;
	struct task_struct *task;
	int ret;

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx_for_tracer(pid, current->tgid);
	task = ctx ? ctx->target : NULL;
	if (task)
		get_task_struct(task);
	spin_unlock_irqrestore(&htrace_lock, flags);

	if (!task)
		return -ESRCH;

	ret = access_process_vm(task, addr, &val, sizeof(val),
				FOLL_FORCE | FOLL_WRITE);
	put_task_struct(task);

	return ret == sizeof(val) ? 0 : -EIO;
}

static long htrace_getregs(pid_t pid, struct user_pt_regs __user *uregs)
{
	struct htrace_context *ctx;
	unsigned long flags;
	struct task_struct *task;
	struct pt_regs *regs;

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx_for_tracer(pid, current->tgid);
	task = ctx ? ctx->target : NULL;
	if (task)
		get_task_struct(task);
	spin_unlock_irqrestore(&htrace_lock, flags);

	if (!task)
		return -ESRCH;

	if (!task_is_stopped_or_traced(task)) {
		put_task_struct(task);
		return -EBUSY;
	}

	regs = task_pt_regs(task);
	if (copy_to_user(uregs, &regs->user_regs, sizeof(regs->user_regs))) {
		put_task_struct(task);
		return -EFAULT;
	}

	put_task_struct(task);
	return 0;
}

static long htrace_setregs(pid_t pid, struct user_pt_regs __user *uregs)
{
	struct htrace_context *ctx;
	unsigned long flags;
	struct task_struct *task;
	struct pt_regs *regs;
	struct user_pt_regs newregs;

	if (copy_from_user(&newregs, uregs, sizeof(newregs)))
		return -EFAULT;

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx_for_tracer(pid, current->tgid);
	task = ctx ? ctx->target : NULL;
	if (task)
		get_task_struct(task);
	spin_unlock_irqrestore(&htrace_lock, flags);

	if (!task)
		return -ESRCH;

	if (!task_is_stopped_or_traced(task)) {
		put_task_struct(task);
		return -EBUSY;
	}

	if (!valid_user_regs(&newregs, task)) {
		put_task_struct(task);
		return -EINVAL;
	}

	regs = task_pt_regs(task);
	regs->user_regs = newregs;
	put_task_struct(task);
	return 0;
}

static long htrace_cont(pid_t pid)
{
	struct htrace_context *ctx;
	unsigned long flags;
	struct task_struct *task;

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx_for_tracer(pid, current->tgid);
	task = ctx ? ctx->target : NULL;
	if (task)
		get_task_struct(task);
	spin_unlock_irqrestore(&htrace_lock, flags);

	if (!task)
		return -ESRCH;

	wake_up_state(task, __TASK_STOPPED);
	put_task_struct(task);
	return 0;
}

static long htrace_singlestep(pid_t pid)
{
	struct htrace_context *ctx;
	unsigned long flags;
	struct task_struct *task;

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx_for_tracer(pid, current->tgid);
	task = ctx ? ctx->target : NULL;
	if (task)
		get_task_struct(task);
	spin_unlock_irqrestore(&htrace_lock, flags);

	if (!task)
		return -ESRCH;

	if (!task_is_stopped(task)) {
		put_task_struct(task);
		return -EBUSY;
	}

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx_for_tracer(pid, current->tgid);
	if (ctx)
		ctx->single_stepping = true;
	spin_unlock_irqrestore(&htrace_lock, flags);

	user_enable_single_step(task);
	wake_up_state(task, __TASK_STOPPED);
	put_task_struct(task);
	return 0;
}

static long htrace_do_kill(pid_t pid)
{
	struct htrace_context *ctx;
	unsigned long flags;
	struct task_struct *task;

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx_for_tracer(pid, current->tgid);
	if (!ctx) {
		spin_unlock_irqrestore(&htrace_lock, flags);
		return -ESRCH;
	}
	task = ctx->target;
	get_task_struct(task);
	hash_del(&ctx->node);
	spin_unlock_irqrestore(&htrace_lock, flags);

	htrace_cleanup_bps(ctx);
	send_sig(SIGKILL, task, 1);
	put_task_struct(task);
	put_task_struct(task);
	kfree(ctx);
	return 0;
}

static long htrace_readmem(pid_t pid, unsigned long uiov_addr,
			   unsigned long count)
{
	struct htrace_context *ctx;
	unsigned long flags;
	struct task_struct *task;
	struct htrace_iovec iov;
	unsigned long i;
	char buf[256];

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx_for_tracer(pid, current->tgid);
	task = ctx ? ctx->target : NULL;
	if (task)
		get_task_struct(task);
	spin_unlock_irqrestore(&htrace_lock, flags);

	if (!task)
		return -ESRCH;

	for (i = 0; i < count; i++) {
		size_t done, chunk;

		if (copy_from_user(&iov,
				   (void __user *)(uiov_addr + i * sizeof(iov)),
				   sizeof(iov))) {
			put_task_struct(task);
			return -EFAULT;
		}

		done = 0;
		while (done < iov.len) {
			int ret;

			chunk = min_t(size_t, iov.len - done, sizeof(buf));
			ret = access_process_vm(task, iov.remote_addr + done,
						buf, chunk, FOLL_FORCE);
			if (ret <= 0) {
				put_task_struct(task);
				return -EIO;
			}
			if (copy_to_user((void __user *)(iov.local_buf + done),
					 buf, ret)) {
				put_task_struct(task);
				return -EFAULT;
			}
			done += ret;
		}
	}

	put_task_struct(task);
	return 0;
}

static long htrace_writemem(pid_t pid, unsigned long uiov_addr,
			    unsigned long count)
{
	struct htrace_context *ctx;
	unsigned long flags;
	struct task_struct *task;
	struct htrace_iovec iov;
	unsigned long i;
	char buf[256];

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx_for_tracer(pid, current->tgid);
	task = ctx ? ctx->target : NULL;
	if (task)
		get_task_struct(task);
	spin_unlock_irqrestore(&htrace_lock, flags);

	if (!task)
		return -ESRCH;

	for (i = 0; i < count; i++) {
		size_t done, chunk;

		if (copy_from_user(&iov,
				   (void __user *)(uiov_addr + i * sizeof(iov)),
				   sizeof(iov))) {
			put_task_struct(task);
			return -EFAULT;
		}

		done = 0;
		while (done < iov.len) {
			int ret;

			chunk = min_t(size_t, iov.len - done, sizeof(buf));
			if (copy_from_user(buf,
					   (void __user *)(iov.local_buf + done),
					   chunk)) {
				put_task_struct(task);
				return -EFAULT;
			}
			ret = access_process_vm(task, iov.remote_addr + done,
						buf, chunk,
						FOLL_FORCE | FOLL_WRITE);
			if (ret <= 0) {
				put_task_struct(task);
				return -EIO;
			}
			done += ret;
		}
	}

	put_task_struct(task);
	return 0;
}

static long htrace_set_hw_bp(pid_t pid, struct htrace_bp_info __user *ubp)
{
	struct htrace_context *ctx;
	unsigned long flags;
	struct htrace_bp_info bp_info;
	struct perf_event_attr attr;
	struct perf_event *bp;
	int slot;

	if (copy_from_user(&bp_info, ubp, sizeof(bp_info)))
		return -EFAULT;

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx_for_tracer(pid, current->tgid);
	if (!ctx) {
		spin_unlock_irqrestore(&htrace_lock, flags);
		return -ESRCH;
	}

	slot = -1;
	{ int i;
	for (i = 0; i < HTRACE_MAX_HW_BPS; i++) {
		if (!ctx->hw_bps[i]) {
			slot = i;
			break;
		}
	} }
	if (slot < 0) {
		spin_unlock_irqrestore(&htrace_lock, flags);
		return -ENOSPC;
	}

	get_task_struct(ctx->target);
	spin_unlock_irqrestore(&htrace_lock, flags);

	hw_breakpoint_init(&attr);
	attr.bp_addr = bp_info.addr;
	attr.bp_type = bp_info.type;
	attr.bp_len = bp_info.len;
	attr.disabled = 0;
	attr.exclude_kernel = 1;

	bp = register_user_hw_breakpoint(&attr, htrace_bp_handler, NULL,
					 ctx->target);
	put_task_struct(ctx->target);

	if (IS_ERR(bp))
		return PTR_ERR(bp);

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx_for_tracer(pid, current->tgid);
	if (!ctx) {
		spin_unlock_irqrestore(&htrace_lock, flags);
		unregister_hw_breakpoint(bp);
		return -ESRCH;
	}
	ctx->hw_bps[slot] = bp;
	ctx->num_hw_bps++;
	spin_unlock_irqrestore(&htrace_lock, flags);

	bp_info.index = slot;
	if (copy_to_user(ubp, &bp_info, sizeof(bp_info)))
		return -EFAULT;

	return 0;
}

static long htrace_del_hw_bp(pid_t pid, int index)
{
	struct htrace_context *ctx;
	unsigned long flags;
	struct perf_event *bp;

	if (index < 0 || index >= HTRACE_MAX_HW_BPS)
		return -EINVAL;

	spin_lock_irqsave(&htrace_lock, flags);
	ctx = htrace_find_ctx_for_tracer(pid, current->tgid);
	if (!ctx) {
		spin_unlock_irqrestore(&htrace_lock, flags);
		return -ESRCH;
	}

	bp = ctx->hw_bps[index];
	if (!bp) {
		spin_unlock_irqrestore(&htrace_lock, flags);
		return -ENOENT;
	}

	ctx->hw_bps[index] = NULL;
	ctx->num_hw_bps--;
	spin_unlock_irqrestore(&htrace_lock, flags);

	unregister_hw_breakpoint(bp);
	return 0;
}

SYSCALL_DEFINE4(htrace, long, request, pid_t, pid,
		unsigned long, addr, unsigned long, data)
{
	if (!capable(CAP_SYS_PTRACE))
		return -EPERM;

	switch (request) {
	case HTRACE_ATTACH:
		return htrace_attach(pid);
	case HTRACE_DETACH:
		return htrace_detach(pid);
	case HTRACE_PEEKDATA:
		return htrace_peekdata(pid, addr,
				       (unsigned long __user *)data);
	case HTRACE_POKEDATA:
		return htrace_pokedata(pid, addr, data);
	case HTRACE_GETREGS:
		return htrace_getregs(pid,
				      (struct user_pt_regs __user *)data);
	case HTRACE_SETREGS:
		return htrace_setregs(pid,
				      (struct user_pt_regs __user *)data);
	case HTRACE_CONT:
		return htrace_cont(pid);
	case HTRACE_SINGLESTEP:
		return htrace_singlestep(pid);
	case HTRACE_KILL:
		return htrace_do_kill(pid);
	case HTRACE_READMEM:
		return htrace_readmem(pid, addr, data);
	case HTRACE_WRITEMEM:
		return htrace_writemem(pid, addr, data);
	case HTRACE_SET_HW_BP:
		return htrace_set_hw_bp(pid,
					(struct htrace_bp_info __user *)data);
	case HTRACE_DEL_HW_BP:
		return htrace_del_hw_bp(pid, (int)addr);
	default:
		return -EINVAL;
	}
}
