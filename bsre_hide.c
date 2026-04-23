/*
 * bsre_hide.ko v2 — Hide TracerPid and thread state via instruction patching
 *
 * ARM64 4.14 ftrace callbacks can't replace functions (no FTRACE_WITH_REGS).
 * Instead, we use aarch64_insn_patch_text to replace the first instruction
 * of proc_pid_status with a branch to our replacement function.
 *
 * Our replacement temporarily zeros task->ptrace, calls the original
 * function (skipping the patched instruction), then restores ptrace.
 *
 * Usage:
 *   insmod bsre_hide.ko target_comm=regeared
 *   rmmod bsre_hide
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/version.h>
#include <asm/insn.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide TracerPid and thread state from BSRE anti-tamper");

static char target_comm[TASK_COMM_LEN] = "";
module_param_string(target_comm, target_comm, sizeof(target_comm), 0644);
MODULE_PARM_DESC(target_comm, "Hide for processes matching this comm substring");

/* Function pointers resolved via kallsyms */
static int (*fn_aarch64_insn_patch_text)(void *addrs[], u32 insns[], int cnt);

/* Original instruction saved for restore */
static u32 orig_status_insn;
static u32 orig_stat_insn;
static void *status_addr;
static void *stat_addr;

/* Original function pointers (entry point + 4 to skip patched instruction) */
typedef int (*proc_pid_status_fn)(struct seq_file *, struct pid_namespace *,
				  struct pid *, struct task_struct *);
typedef int (*do_task_stat_fn)(struct seq_file *, struct pid_namespace *,
			       struct pid *, struct task_struct *, int);

static proc_pid_status_fn orig_proc_pid_status_skip;
static do_task_stat_fn orig_do_task_stat_skip;

static bool should_hide(struct task_struct *task)
{
	if (!task)
		return false;
	if (target_comm[0] == '\0')
		return true;
	return strstr(task->comm, target_comm) != NULL;
}

/* Replacement for proc_pid_status */
static int replacement_proc_pid_status(struct seq_file *m,
	struct pid_namespace *ns, struct pid *pid, struct task_struct *task)
{
	int ret;
	unsigned int saved_ptrace = 0;
	bool hiding = false;

	if (should_hide(task) && task->ptrace) {
		saved_ptrace = task->ptrace;
		task->ptrace = 0;
		hiding = true;
		pr_debug("bsre_hide: hiding ptrace=%u for %s (pid %d)\n",
			 saved_ptrace, task->comm, task->pid);
	}

	/* Call original function, skipping the first instruction (which is our branch) */
	ret = orig_proc_pid_status_skip(m, ns, pid, task);

	if (hiding)
		task->ptrace = saved_ptrace;

	return ret;
}

/* Replacement for do_task_stat */
static int replacement_do_task_stat(struct seq_file *m,
	struct pid_namespace *ns, struct pid *pid,
	struct task_struct *task, int whole)
{
	int ret;
	long saved_state = 0;
	bool hiding = false;

	if (should_hide(task) && (task->state & TASK_TRACED)) {
		saved_state = task->state;
		task->state = TASK_INTERRUPTIBLE;
		hiding = true;
	}

	ret = orig_do_task_stat_skip(m, ns, pid, task, whole);

	if (hiding)
		task->state = saved_state;

	return ret;
}

static u32 make_branch_insn(void *from, void *to)
{
	long offset = (long)to - (long)from;
	/* ARM64 B instruction: offset is in 4-byte units, 26-bit signed */
	if (offset < -(1 << 27) || offset >= (1 << 27)) {
		pr_err("bsre_hide: branch offset too large: %ld\n", offset);
		return 0;
	}
	return 0x14000000 | ((offset >> 2) & 0x03FFFFFF);
}

static int patch_function(void *target, void *replacement, u32 *saved_insn,
			  const char *name)
{
	u32 branch;
	void *addrs[1];
	u32 insns[1];

	/* Save original instruction */
	*saved_insn = *(u32 *)target;
	pr_info("bsre_hide: %s @ %px, original insn: 0x%08x\n",
		name, target, *saved_insn);

	/* Create branch instruction to our replacement */
	branch = make_branch_insn(target, replacement);
	if (!branch)
		return -EINVAL;

	/* Patch */
	addrs[0] = target;
	insns[0] = branch;
	fn_aarch64_insn_patch_text(addrs, insns, 1);

	pr_info("bsre_hide: patched %s with B 0x%08x → %px\n",
		name, branch, replacement);
	return 0;
}

static void restore_function(void *target, u32 saved_insn, const char *name)
{
	void *addrs[1];
	u32 insns[1];

	addrs[0] = target;
	insns[0] = saved_insn;
	fn_aarch64_insn_patch_text(addrs, insns, 1);

	pr_info("bsre_hide: restored %s original insn 0x%08x\n", name, saved_insn);
}

static int __init bsre_hide_init(void)
{
	int ret;

	pr_info("bsre_hide: loading (target_comm='%s')\n", target_comm);

	/* Resolve kallsyms */
	fn_aarch64_insn_patch_text = (void *)kallsyms_lookup_name("aarch64_insn_patch_text");
	if (!fn_aarch64_insn_patch_text) {
		pr_err("bsre_hide: can't find aarch64_insn_patch_text\n");
		return -ENOENT;
	}

	status_addr = (void *)kallsyms_lookup_name("proc_pid_status");
	if (!status_addr) {
		pr_err("bsre_hide: can't find proc_pid_status\n");
		return -ENOENT;
	}

	stat_addr = (void *)kallsyms_lookup_name("do_task_stat");
	if (!stat_addr) {
		pr_err("bsre_hide: can't find do_task_stat\n");
		return -ENOENT;
	}

	/* Set up "skip first instruction" entry points */
	orig_proc_pid_status_skip = (proc_pid_status_fn)((char *)status_addr + 4);
	orig_do_task_stat_skip = (do_task_stat_fn)((char *)stat_addr + 4);

	/* Patch proc_pid_status */
	ret = patch_function(status_addr, replacement_proc_pid_status,
			     &orig_status_insn, "proc_pid_status");
	if (ret)
		return ret;

	/* Patch do_task_stat */
	ret = patch_function(stat_addr, replacement_do_task_stat,
			     &orig_stat_insn, "do_task_stat");
	if (ret) {
		restore_function(status_addr, orig_status_insn, "proc_pid_status");
		return ret;
	}

	pr_info("bsre_hide: loaded — TracerPid + thread state hiding active\n");
	return 0;
}

static void __exit bsre_hide_exit(void)
{
	restore_function(stat_addr, orig_stat_insn, "do_task_stat");
	restore_function(status_addr, orig_status_insn, "proc_pid_status");
	pr_info("bsre_hide: unloaded\n");
}

module_init(bsre_hide_init);
module_exit(bsre_hide_exit);
