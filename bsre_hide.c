/*
 * bsre_hide.ko v3 — Hide TracerPid and thread state via instruction patching
 *
 * v2 bug: skipping the first instruction (STP frame setup) corrupted the
 * stack frame, causing the replacement function to receive garbage args.
 * v3 fix: allocate executable trampoline that executes the saved original
 * instruction then branches to orig_func+4.
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
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/insn.h>
#include <asm/cacheflush.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide TracerPid and thread state from BSRE anti-tamper v3");

static char target_comm[TASK_COMM_LEN] = "";
module_param_string(target_comm, target_comm, sizeof(target_comm), 0644);

/* Function pointers resolved via kallsyms */
static int (*fn_aarch64_insn_patch_text)(void *addrs[], u32 insns[], int cnt);

/* Hook state */
struct hook_state {
	const char *name;
	void *orig_addr;
	u32 orig_insn;
	void *trampoline;	/* executable: orig_insn + B orig+4 */
	void *replacement;
	bool active;
};

static struct hook_state status_hook;
static struct hook_state stat_hook;

/* Original function typedefs — called via trampoline */
typedef int (*proc_pid_status_fn)(struct seq_file *, struct pid_namespace *,
				  struct pid *, struct task_struct *);
typedef int (*do_task_stat_fn)(struct seq_file *, struct pid_namespace *,
			       struct pid *, struct task_struct *, int);

static bool should_hide(struct task_struct *task)
{
	if (!task)
		return false;
	if (target_comm[0] == '\0')
		return true;
	return strstr(task->comm, target_comm) != NULL;
}

/* Replacement for proc_pid_status */
static int repl_proc_pid_status(struct seq_file *m,
	struct pid_namespace *ns, struct pid *pid, struct task_struct *task)
{
	int ret;
	unsigned int saved = 0;
	bool hiding = false;

	if (should_hide(task) && task->ptrace) {
		saved = task->ptrace;
		task->ptrace = 0;
		hiding = true;
	}

	/* Call original via trampoline (executes saved insn + jumps to orig+4) */
	ret = ((proc_pid_status_fn)status_hook.trampoline)(m, ns, pid, task);

	if (hiding)
		task->ptrace = saved;

	return ret;
}

/* Replacement for do_task_stat */
static int repl_do_task_stat(struct seq_file *m,
	struct pid_namespace *ns, struct pid *pid,
	struct task_struct *task, int whole)
{
	int ret;
	long saved = 0;
	bool hiding = false;

	if (should_hide(task) && (task->state & TASK_TRACED)) {
		saved = task->state;
		task->state = TASK_INTERRUPTIBLE;
		hiding = true;
	}

	ret = ((do_task_stat_fn)stat_hook.trampoline)(m, ns, pid, task, whole);

	if (hiding)
		task->state = saved;

	return ret;
}

/*
 * Build a trampoline: 2 instructions
 *   [0] = original saved instruction (e.g., STP X29, X30, [SP, #-0xC0]!)
 *   [4] = B (orig_addr + 4)  — branch to rest of original function
 *
 * The trampoline must be in executable memory.
 */
static void *build_trampoline(u32 saved_insn, void *orig_addr)
{
	u32 *tramp;
	long offset;

	/* Allocate executable page */
	tramp = __vmalloc(PAGE_SIZE, GFP_KERNEL, PAGE_KERNEL_EXEC);
	if (!tramp) {
		pr_err("bsre_hide: failed to allocate trampoline\n");
		return NULL;
	}

	/* Instruction 1: the original saved instruction */
	tramp[0] = saved_insn;

	/* Instruction 2: B (orig_addr + 4) */
	offset = (long)((char *)orig_addr + 4) - (long)&tramp[1];
	if (offset < -(1 << 27) || offset >= (1 << 27)) {
		pr_err("bsre_hide: trampoline branch offset too large\n");
		vfree(tramp);
		return NULL;
	}
	tramp[1] = 0x14000000 | ((offset >> 2) & 0x03FFFFFF);

	/* Flush caches */
	flush_icache_range((unsigned long)tramp, (unsigned long)&tramp[2]);

	pr_info("bsre_hide: trampoline @ %px: insn=0x%08x B→%px\n",
		tramp, saved_insn, (char *)orig_addr + 4);
	return tramp;
}

static u32 make_branch(void *from, void *to)
{
	long offset = (long)to - (long)from;
	if (offset < -(1 << 27) || offset >= (1 << 27)) {
		pr_err("bsre_hide: branch offset too large: %ld\n", offset);
		return 0;
	}
	return 0x14000000 | ((offset >> 2) & 0x03FFFFFF);
}

static int install_hook(struct hook_state *h, void *replacement)
{
	u32 branch;
	void *addrs[1];
	u32 insns[1];

	/* Save original instruction */
	h->orig_insn = *(u32 *)h->orig_addr;
	h->replacement = replacement;

	/* Build trampoline */
	h->trampoline = build_trampoline(h->orig_insn, h->orig_addr);
	if (!h->trampoline)
		return -ENOMEM;

	/* Patch function entry with B to replacement */
	branch = make_branch(h->orig_addr, replacement);
	if (!branch) {
		vfree(h->trampoline);
		return -EINVAL;
	}

	addrs[0] = h->orig_addr;
	insns[0] = branch;
	fn_aarch64_insn_patch_text(addrs, insns, 1);

	h->active = true;
	pr_info("bsre_hide: hooked %s @ %px → %px (tramp @ %px)\n",
		h->name, h->orig_addr, replacement, h->trampoline);
	return 0;
}

static void remove_hook(struct hook_state *h)
{
	void *addrs[1];
	u32 insns[1];

	if (!h->active)
		return;

	/* Restore original instruction */
	addrs[0] = h->orig_addr;
	insns[0] = h->orig_insn;
	fn_aarch64_insn_patch_text(addrs, insns, 1);

	/* Free trampoline */
	if (h->trampoline)
		vfree(h->trampoline);

	h->active = false;
	pr_info("bsre_hide: unhooked %s\n", h->name);
}

static int __init bsre_hide_init(void)
{
	int ret;

	pr_info("bsre_hide v3: loading (target_comm='%s')\n", target_comm);

	fn_aarch64_insn_patch_text = (void *)kallsyms_lookup_name("aarch64_insn_patch_text");
	if (!fn_aarch64_insn_patch_text) {
		pr_err("bsre_hide: can't find aarch64_insn_patch_text\n");
		return -ENOENT;
	}

	status_hook.name = "proc_pid_status";
	status_hook.orig_addr = (void *)kallsyms_lookup_name("proc_pid_status");
	if (!status_hook.orig_addr) {
		pr_err("bsre_hide: can't find proc_pid_status\n");
		return -ENOENT;
	}

	stat_hook.name = "do_task_stat";
	stat_hook.orig_addr = (void *)kallsyms_lookup_name("do_task_stat");
	if (!stat_hook.orig_addr) {
		pr_err("bsre_hide: can't find do_task_stat\n");
		return -ENOENT;
	}

	ret = install_hook(&status_hook, repl_proc_pid_status);
	if (ret)
		return ret;

	ret = install_hook(&stat_hook, repl_do_task_stat);
	if (ret) {
		remove_hook(&status_hook);
		return ret;
	}

	pr_info("bsre_hide v3: loaded — TracerPid + thread state hiding active\n");
	return 0;
}

static void __exit bsre_hide_exit(void)
{
	remove_hook(&stat_hook);
	remove_hook(&status_hook);
	pr_info("bsre_hide v3: unloaded\n");
}

module_init(bsre_hide_init);
module_exit(bsre_hide_exit);
