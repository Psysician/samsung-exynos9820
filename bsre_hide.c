/*
 * bsre_hide.ko v3.1 — Fix: use indirect branch in trampoline (LDR X16, addr; BR X16)
 * Direct B has ±128MB range limit, vmalloc is too far from kernel text.
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
MODULE_DESCRIPTION("Hide TracerPid and thread state v3.1 — indirect branch trampoline");

static char target_comm[TASK_COMM_LEN] = "";
module_param_string(target_comm, target_comm, sizeof(target_comm), 0644);

static int (*fn_patch_text)(void *addrs[], u32 insns[], int cnt);

struct hook_state {
	const char *name;
	void *orig_addr;
	u32 orig_insn;
	void *trampoline;
	bool active;
};

static struct hook_state status_hook;
static struct hook_state stat_hook;

typedef int (*status_fn_t)(struct seq_file *, struct pid_namespace *,
			   struct pid *, struct task_struct *);
typedef int (*stat_fn_t)(struct seq_file *, struct pid_namespace *,
			 struct pid *, struct task_struct *, int);

static bool should_hide(struct task_struct *task)
{
	if (!task) return false;
	if (target_comm[0] == '\0') return true;
	return strstr(task->comm, target_comm) != NULL;
}

static int repl_status(struct seq_file *m, struct pid_namespace *ns,
		       struct pid *pid, struct task_struct *task)
{
	int ret;
	unsigned int saved = 0;
	bool hiding = false;

	if (should_hide(task) && task->ptrace) {
		saved = task->ptrace;
		task->ptrace = 0;
		hiding = true;
	}

	ret = ((status_fn_t)status_hook.trampoline)(m, ns, pid, task);

	if (hiding)
		task->ptrace = saved;

	return ret;
}

static int repl_stat(struct seq_file *m, struct pid_namespace *ns,
		     struct pid *pid, struct task_struct *task, int whole)
{
	int ret;
	long saved = 0;
	bool hiding = false;

	if (should_hide(task) && (task->state & TASK_TRACED)) {
		saved = task->state;
		task->state = TASK_INTERRUPTIBLE;
		hiding = true;
	}

	ret = ((stat_fn_t)stat_hook.trampoline)(m, ns, pid, task, whole);

	if (hiding)
		task->state = saved;

	return ret;
}

/*
 * Trampoline layout (4 instructions = 16 bytes):
 *   [0] saved_insn          — original first instruction (e.g., STP X29,X30,[SP,#-0xC0]!)
 *   [4] LDR X16, [PC, #8]   — load target address from [12]
 *   [8] BR X16              — indirect branch to orig_func+4
 *  [12] <64-bit address>    — orig_func + 4
 */
static void *build_trampoline(u32 saved_insn, void *orig_addr)
{
	u32 *t;
	u64 target = (u64)orig_addr + 4;

	t = __vmalloc(PAGE_SIZE, GFP_KERNEL, PAGE_KERNEL_EXEC);
	if (!t) return NULL;

	t[0] = saved_insn;		/* original instruction */
	t[1] = 0x58000050;		/* LDR X16, [PC, #8] (literal load, offset=+8 bytes=2 insns) */
	t[2] = 0xd61f0200;		/* BR X16 */
	t[3] = (u32)(target & 0xFFFFFFFF);	/* low 32 bits of address */
	t[4] = (u32)(target >> 32);		/* high 32 bits of address */

	flush_icache_range((unsigned long)t, (unsigned long)&t[5]);

	pr_info("bsre_hide: trampoline @ %px → insn=0x%08x → jump %px\n",
		t, saved_insn, (void *)target);
	return t;
}

static u32 make_branch(void *from, void *to)
{
	long off = (long)to - (long)from;
	if (off < -(1 << 27) || off >= (1 << 27)) {
		pr_err("bsre_hide: branch %px→%px offset %ld too large\n", from, to, off);
		return 0;
	}
	return 0x14000000 | ((off >> 2) & 0x03FFFFFF);
}

static int install_hook(struct hook_state *h, void *replacement)
{
	u32 branch, insns[1];
	void *addrs[1];

	h->orig_insn = *(u32 *)h->orig_addr;
	h->trampoline = build_trampoline(h->orig_insn, h->orig_addr);
	if (!h->trampoline) return -ENOMEM;

	branch = make_branch(h->orig_addr, replacement);
	if (!branch) { vfree(h->trampoline); return -EINVAL; }

	addrs[0] = h->orig_addr;
	insns[0] = branch;
	fn_patch_text(addrs, insns, 1);

	h->active = true;
	pr_info("bsre_hide: hooked %s @ %px (insn 0x%08x → B %px)\n",
		h->name, h->orig_addr, h->orig_insn, replacement);
	return 0;
}

static void remove_hook(struct hook_state *h)
{
	u32 insns[1]; void *addrs[1];
	if (!h->active) return;
	addrs[0] = h->orig_addr;
	insns[0] = h->orig_insn;
	fn_patch_text(addrs, insns, 1);
	if (h->trampoline) vfree(h->trampoline);
	h->active = false;
	pr_info("bsre_hide: unhooked %s\n", h->name);
}

static int __init bsre_hide_init(void)
{
	int ret;
	pr_info("bsre_hide v3.1: loading (target='%s')\n", target_comm);

	fn_patch_text = (void *)kallsyms_lookup_name("aarch64_insn_patch_text");
	if (!fn_patch_text) { pr_err("bsre_hide: no patch_text\n"); return -ENOENT; }

	status_hook.name = "proc_pid_status";
	status_hook.orig_addr = (void *)kallsyms_lookup_name("proc_pid_status");
	stat_hook.name = "do_task_stat";
	stat_hook.orig_addr = (void *)kallsyms_lookup_name("do_task_stat");

	if (!status_hook.orig_addr || !stat_hook.orig_addr) {
		pr_err("bsre_hide: symbol not found\n");
		return -ENOENT;
	}

	ret = install_hook(&status_hook, repl_status);
	if (ret) return ret;

	ret = install_hook(&stat_hook, repl_stat);
	if (ret) { remove_hook(&status_hook); return ret; }

	pr_info("bsre_hide v3.1: active\n");
	return 0;
}

static void __exit bsre_hide_exit(void)
{
	remove_hook(&stat_hook);
	remove_hook(&status_hook);
	pr_info("bsre_hide v3.1: unloaded\n");
}

module_init(bsre_hide_init);
module_exit(bsre_hide_exit);
