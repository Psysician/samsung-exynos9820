/*
 * bsac_hook.c - Intercept kill syscalls for anti-cheat bypass
 *
 * Hooks exit_group(94), kill(129), tgkill(131) on arm64.
 * Suppresses when target process comm contains "brawlstar".
 *
 * Uses SCTLR_EL1 WXN bit to temporarily make sys_call_table writable.
 * No pgtable headers needed — pure inline asm approach.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/pid.h>
#include <linux/rcupdate.h>
#include <linux/preempt.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Syscall hook to prevent process termination");

#define TARGET_COMM "brawlstar"

static void **sys_call_table;

typedef asmlinkage long (*syscall_fn_t)(const struct pt_regs *regs);

static syscall_fn_t orig_exit_group;
static syscall_fn_t orig_kill;
static syscall_fn_t orig_tgkill;

static unsigned long saved_sctlr;

static void wp_disable(void)
{
	unsigned long val;
	preempt_disable();
	asm volatile("mrs %0, sctlr_el1" : "=r"(val));
	saved_sctlr = val;
	val &= ~(1UL << 19);
	asm volatile("msr sctlr_el1, %0\nisb" : : "r"(val));
}

static void wp_restore(void)
{
	asm volatile("msr sctlr_el1, %0\nisb" : : "r"(saved_sctlr));
	preempt_enable();
}

static bool is_target_pid(pid_t pid)
{
	struct task_struct *task;
	bool match = false;
	rcu_read_lock();
	task = pid_task(find_vpid(pid), PIDTYPE_PID);
	if (task && strstr(task->comm, TARGET_COMM))
		match = true;
	rcu_read_unlock();
	return match;
}

static asmlinkage long hook_exit_group(const struct pt_regs *regs)
{
	if (strstr(current->comm, TARGET_COMM)) {
		pr_info("bsac_hook: blocked exit_group pid=%d\n", current->pid);
		return 0;
	}
	return orig_exit_group(regs);
}

static asmlinkage long hook_kill(const struct pt_regs *regs)
{
	pid_t pid = (pid_t)regs->regs[0];
	int sig = (int)regs->regs[1];
	if ((sig == SIGABRT || sig == SIGKILL) && is_target_pid(pid)) {
		pr_info("bsac_hook: blocked kill(%d,%d)\n", pid, sig);
		return 0;
	}
	return orig_kill(regs);
}

static asmlinkage long hook_tgkill(const struct pt_regs *regs)
{
	pid_t tid = (pid_t)regs->regs[1];
	int sig = (int)regs->regs[2];
	if ((sig == SIGABRT || sig == SIGKILL) && is_target_pid(tid)) {
		pr_info("bsac_hook: blocked tgkill(%d,%d)\n", tid, sig);
		return 0;
	}
	return orig_tgkill(regs);
}

static int __init bsac_hook_init(void)
{
	sys_call_table = (void **)kallsyms_lookup_name("sys_call_table");
	if (!sys_call_table) {
		pr_err("bsac_hook: sys_call_table not found\n");
		return -ENOENT;
	}
	pr_info("bsac_hook: sys_call_table @ %px\n", sys_call_table);

	orig_exit_group = (syscall_fn_t)sys_call_table[94];
	orig_kill       = (syscall_fn_t)sys_call_table[129];
	orig_tgkill     = (syscall_fn_t)sys_call_table[131];

	wp_disable();
	sys_call_table[94]  = (void *)hook_exit_group;
	sys_call_table[129] = (void *)hook_kill;
	sys_call_table[131] = (void *)hook_tgkill;
	wp_restore();

	pr_info("bsac_hook: hooks installed\n");
	return 0;
}

static void __exit bsac_hook_exit(void)
{
	wp_disable();
	sys_call_table[94]  = (void *)orig_exit_group;
	sys_call_table[129] = (void *)orig_kill;
	sys_call_table[131] = (void *)orig_tgkill;
	wp_restore();
	pr_info("bsac_hook: unloaded\n");
}

module_init(bsac_hook_init);
module_exit(bsac_hook_exit);
