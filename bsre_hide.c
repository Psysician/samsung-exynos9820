/*
 * bsre_hide.ko v4 — Hide TracerPid via seq_file output patching
 *
 * v3 bug: setting task->ptrace=0 doesn't affect ptrace_parent() which
 * uses the parent task link, not the ptrace field. TracerPid was still visible.
 *
 * v4 fix: let proc_pid_status run normally, then post-process the seq_file
 * output buffer to replace "TracerPid:\tNNN" with "TracerPid:\t0".
 * Also hides thread state via do_task_stat (working since v2).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hide TracerPid + thread state v4 — output patching");

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

/*
 * Post-process seq_file buffer to replace TracerPid value with 0.
 * Searches for "TracerPid:\tNNN\n" and overwrites NNN with "0  " (padded).
 */
static void patch_tracer_pid(struct seq_file *m, size_t start_pos)
{
	char *buf = m->buf;
	size_t end = m->count;
	char *p, *nl, *val;
	size_t i;

	if (!buf || end <= start_pos)
		return;

	/* Search for "TracerPid:\t" in the new output */
	for (i = start_pos; i + 12 < end; i++) {
		if (buf[i] == 'T' && buf[i+1] == 'r' &&
		    memcmp(&buf[i], "TracerPid:\t", 11) == 0) {
			val = &buf[i + 11]; /* start of the number */
			nl = memchr(val, '\n', end - (val - buf));
			if (!nl) break;
			/* Overwrite number with "0" + spaces */
			*val = '0';
			memset(val + 1, ' ', nl - val - 1);
			return;
		}
	}
}

/* Replacement for proc_pid_status: call original, then patch output */
static int repl_status(struct seq_file *m, struct pid_namespace *ns,
		       struct pid *pid, struct task_struct *task)
{
	int ret;
	size_t before;

	if (!should_hide(task))
		return ((status_fn_t)status_hook.trampoline)(m, ns, pid, task);

	before = m->count;
	pr_info("bsre_hide: repl_status called for %s pid=%d before=%zu\n", task->comm, task->pid, before);
	ret = ((status_fn_t)status_hook.trampoline)(m, ns, pid, task);
	pr_info("bsre_hide: repl_status after count=%zu\n", m->count);
	patch_tracer_pid(m, before);

	return ret;
}

/* Replacement for do_task_stat: hide thread state T */
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

/* Trampoline: saved_insn + LDR X16,[PC,#8] + BR X16 + 64-bit addr */
static void *build_trampoline(u32 saved_insn, void *orig_addr)
{
	u32 *t;
	u64 target = (u64)orig_addr + 4;

	t = __vmalloc(PAGE_SIZE, GFP_KERNEL, PAGE_KERNEL_EXEC);
	if (!t) return NULL;

	t[0] = saved_insn;
	t[1] = 0x58000050;	/* LDR X16, [PC, #8] */
	t[2] = 0xd61f0200;	/* BR X16 */
	t[3] = (u32)(target & 0xFFFFFFFF);
	t[4] = (u32)(target >> 32);

	flush_icache_range((unsigned long)t, (unsigned long)&t[5]);
	return t;
}

static u32 make_branch(void *from, void *to)
{
	long off = (long)to - (long)from;
	if (off < -(1 << 27) || off >= (1 << 27)) return 0;
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
	pr_info("bsre_hide: hooked %s\n", h->name);
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
	pr_info("bsre_hide v4: loading (target='%s')\n", target_comm);

	fn_patch_text = (void *)kallsyms_lookup_name("aarch64_insn_patch_text");
	if (!fn_patch_text) return -ENOENT;

	status_hook.name = "proc_pid_status";
	status_hook.orig_addr = (void *)kallsyms_lookup_name("proc_pid_status");
	stat_hook.name = "do_task_stat";
	stat_hook.orig_addr = (void *)kallsyms_lookup_name("do_task_stat");
	if (!status_hook.orig_addr || !stat_hook.orig_addr) return -ENOENT;

	ret = install_hook(&status_hook, repl_status);
	if (ret) return ret;
	ret = install_hook(&stat_hook, repl_stat);
	if (ret) { remove_hook(&status_hook); return ret; }

	pr_info("bsre_hide v4: active — TracerPid output patching + thread state hiding\n");
	return 0;
}

static void __exit bsre_hide_exit(void)
{
	remove_hook(&stat_hook);
	remove_hook(&status_hook);
	pr_info("bsre_hide v4: unloaded\n");
}

module_init(bsre_hide_init);
module_exit(bsre_hide_exit);
