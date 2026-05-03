#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/io.h>
#include "hyp_s2.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ARM64 EL2 hypervisor stage-2 capture — multi-target + auto-dump");
MODULE_VERSION("2.1");

#define VECTORS_SIZE	4096
#define NR_CPUS_MAX	8
#define KSYM_BUF_SIZE	(3 * 1024 * 1024)

static int target_pid;
module_param(target_pid, int, 0444);
MODULE_PARM_DESC(target_pid, "PID (0 = use watcher)");

static unsigned long target_addr;
module_param(target_addr, ulong, 0444);
MODULE_PARM_DESC(target_addr, "VA to trap on (0 = auto from lib)");

static char *watch_name = "regeared";
module_param(watch_name, charp, 0444);
MODULE_PARM_DESC(watch_name, "Process name to watch for");

static char *lib_name = "libregeared.so";
module_param(lib_name, charp, 0444);
MODULE_PARM_DESC(lib_name, "Library to find in maps");

static unsigned long lib_offset = 0x5371C4;
module_param(lib_offset, ulong, 0444);
MODULE_PARM_DESC(lib_offset, "ELF offset (single-target, legacy)");

static char *target_offsets = "";
module_param(target_offsets, charp, 0444);
MODULE_PARM_DESC(target_offsets, "Comma-separated hex offsets (e.g. 0x5371C4,0x831C28)");

static char *target_types = "";
module_param(target_types, charp, 0444);
MODULE_PARM_DESC(target_types, "Comma-separated: exec or data (default: exec)");

static char *target_actions = "";
module_param(target_actions, charp, 0444);
MODULE_PARM_DESC(target_actions, "Comma-separated: capture,patch,skip (default: capture)");

static char *patch_x0_vals = "";
module_param(patch_x0_vals, charp, 0444);
MODULE_PARM_DESC(patch_x0_vals, "Comma-separated hex x0 patch values");

static char *patch_pc_vals = "";
module_param(patch_pc_vals, charp, 0444);
MODULE_PARM_DESC(patch_pc_vals, "Comma-separated hex PC patch values");

static unsigned long custom_uh_pa;
module_param(custom_uh_pa, ulong, 0444);
MODULE_PARM_DESC(custom_uh_pa, "PA of custom UH vector page (skip set_vectors)");

static int one_shot = 1;
module_param(one_shot, int, 0444);
MODULE_PARM_DESC(one_shot, "Don't re-arm after capture (default: 1)");

static char *dump_regs = "";
module_param(dump_regs, charp, 0444);
MODULE_PARM_DESC(dump_regs, "Per-target register index to dump memory at (e.g. 1,3)");

static unsigned long dump_size = 0x80000;
module_param(dump_size, ulong, 0444);
MODULE_PARM_DESC(dump_size, "Bytes to dump per captured pointer (default: 512KB)");

static unsigned long arm_delay_ms = 0;
module_param(arm_delay_ms, ulong, 0444);
MODULE_PARM_DESC(arm_delay_ms, "Wait this long after lib found before arming (default: 0)");

static char *trigger_map = "";
module_param(trigger_map, charp, 0444);
MODULE_PARM_DESC(trigger_map, "Per-target trigger: which target must capture first (-1=immediate, e.g. -1,0)");

static unsigned long pre_arm_pa = 0;
module_param(pre_arm_pa, ulong, 0444);
MODULE_PARM_DESC(pre_arm_pa, "PA to pre-arm XN on at init (from previous run, skip VA resolution)");

/* External symbols from hyp_vectors.S */
extern char hypsniff_vectors[];
extern char hypsniff_shared_pa_slot[];
extern char hypsniff_vectors_end[];

/* Resolved via /proc/kallsyms */
typedef void (*hyp_set_vectors_fn)(phys_addr_t);
typedef void (*on_each_cpu_fn)(void (*)(void *), void *, int);

static hyp_set_vectors_fn kfn_hyp_set_vectors;
static on_each_cpu_fn kfn_on_each_cpu;
static phys_addr_t orig_vectors_pa;

get_free_pages_fn kfn_get_free_pages;
free_pages_fn kfn_free_pages;

/* Per-target configuration (EL1-side) */
struct target_config {
	unsigned long lib_offset;
	int type;
	int action;
	u64 patch_x0;
	u64 patch_pc;
	unsigned long va;
	phys_addr_t pa;
	phys_addr_t pte_pa;
	int armed;
	int captured;
	int trigger_idx;	/* don't arm until this target captures (-1 = arm immediately) */
	int dump_reg;		/* register index to dump memory at (-1 = none) */
	int dump_done;
	long dump_bytes;	/* bytes actually dumped */
};

/* State */
static struct s2_tables s2;
static struct hyp_shared_data *shared;
static struct hyp_capture_entry *cap_entries;
static struct hyp_target_desc *hyp_targets;	/* EL2-visible target descriptors */
static phys_addr_t shared_pa;
static void *vector_page;
static phys_addr_t vector_page_pa;
static void *stack_pages[NR_CPUS_MAX];
static phys_addr_t stack_pas[NR_CPUS_MAX];
static int vectors_installed;
static int boot_vectors;	/* 1 if using boot-installed vectors */
static int s2_enabled;
static int watched_pid;

static struct target_config targets[MAX_TARGETS];
static int num_targets;

static struct task_struct *watcher_thread;
static struct proc_dir_entry *proc_entry;
static struct proc_dir_entry *proc_dump_entry;

/* Memory dump buffer — exposed via /proc/hypsniff_dump */
#define MAX_DUMP_SIZE	(512 * 1024)
static char *dump_buf;
static long dump_buf_len;

/* ===================== AT-instruction VA->PA ===================== */

static phys_addr_t at_virt_to_phys(void *va)
{
	u64 par;

	asm volatile(
		"at s1e1r, %1\n"
		"isb\n"
		"mrs %0, par_el1\n"
		: "=r"(par)
		: "r"((u64)va)
	);
	if (par & 1)
		return 0;
	return (par & 0xFFFFFFFFF000ULL) | ((u64)va & 0xFFF);
}

/* ===================== Inline dcache flush ===================== */

static void flush_dcache_range(void *addr, size_t len)
{
	u64 line_size = 64;
	u64 start = (u64)addr & ~(line_size - 1);
	u64 end = (u64)addr + len;

	for (; start < end; start += line_size)
		asm volatile("dc civac, %0" :: "r"(start) : "memory");
	asm volatile("dsb ish" ::: "memory");
}

/* ===================== /proc/kallsyms resolver ===================== */

static int ksym_strlen(const char *s)
{
	int len = 0;
	while (s[len])
		len++;
	return len;
}

static unsigned long resolve_ksym(const char *name)
{
	struct file *f;
	char *buf, *line, *end, *p;
	int total = 0, n, namelen;
	loff_t pos = 0;
	unsigned long addr = 0;

	namelen = ksym_strlen(name);

	f = filp_open("/proc/kallsyms", O_RDONLY, 0);
	if (IS_ERR(f))
		return 0;

	buf = kmalloc(KSYM_BUF_SIZE, GFP_KERNEL);
	if (!buf) {
		filp_close(f, NULL);
		return 0;
	}

	while (total < KSYM_BUF_SIZE - 1) {
		n = kernel_read(f, buf + total, KSYM_BUF_SIZE - 1 - total, &pos);
		if (n <= 0)
			break;
		total += n;
	}
	buf[total] = 0;
	filp_close(f, NULL);

	line = buf;
	while (line < buf + total) {
		end = strchr(line, '\n');
		if (end)
			*end = 0;
		else
			end = buf + total;

		addr = simple_strtoul(line, &p, 16);
		if (p == line || !*p)
			goto next;

		while (*p == ' ') p++;
		if (!*p) goto next;
		p++;
		while (*p == ' ') p++;
		if (!*p) goto next;

		if (strstr(p, name) == p) {
			char c = p[namelen];
			if (c == '\0' || c == ' ' || c == '\t' || c == '\n') {
				kfree(buf);
				return addr;
			}
		}
		addr = 0;
next:
		line = end + 1;
	}

	kfree(buf);
	return 0;
}

/* ===================== Target parameter parsing ===================== */

static int parse_target_params(void)
{
	char *buf, *tok, *p;
	int i;

	for (i = 0; i < MAX_TARGETS; i++) {
		targets[i].dump_reg = -1;
		targets[i].trigger_idx = -1;
		targets[i].captured = 0;
		targets[i].dump_done = 0;
		targets[i].dump_bytes = 0;
	}

	if (target_offsets[0] == '\0') {
		targets[0].lib_offset = lib_offset;
		targets[0].type = TARGET_TYPE_EXEC;
		targets[0].action = PATCH_ACTION_CAPTURE;
		targets[0].patch_x0 = 0;
		targets[0].patch_pc = 0;
		num_targets = 1;
		pr_info("hypsniff: single target: offset=0x%lx\n", lib_offset);
		goto parse_dump_regs;
	}

	/* Parse target_offsets */
	buf = kstrdup(target_offsets, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	p = buf;
	i = 0;
	while ((tok = strsep(&p, ",")) != NULL && i < MAX_TARGETS) {
		if (tok[0] == '\0')
			continue;
		targets[i].lib_offset = simple_strtoul(tok, NULL, 0);
		targets[i].type = TARGET_TYPE_EXEC;
		targets[i].action = PATCH_ACTION_CAPTURE;
		targets[i].patch_x0 = 0;
		targets[i].patch_pc = 0;
		i++;
	}
	num_targets = i;
	kfree(buf);

	if (num_targets == 0) {
		pr_err("hypsniff: no valid target offsets\n");
		return -EINVAL;
	}

	/* Parse target_types */
	if (target_types[0] != '\0') {
		buf = kstrdup(target_types, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		p = buf;
		i = 0;
		while ((tok = strsep(&p, ",")) != NULL && i < num_targets) {
			if (tok[0] == '\0')
				continue;
			if (strcmp(tok, "data") == 0)
				targets[i].type = TARGET_TYPE_DATA;
			else
				targets[i].type = TARGET_TYPE_EXEC;
			i++;
		}
		kfree(buf);
	}

	/* Parse target_actions */
	if (target_actions[0] != '\0') {
		buf = kstrdup(target_actions, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		p = buf;
		i = 0;
		while ((tok = strsep(&p, ",")) != NULL && i < num_targets) {
			if (tok[0] == '\0')
				continue;
			if (strcmp(tok, "patch") == 0)
				targets[i].action = PATCH_ACTION_PATCH;
			else if (strcmp(tok, "skip") == 0)
				targets[i].action = PATCH_ACTION_SKIP;
			else
				targets[i].action = PATCH_ACTION_CAPTURE;
			i++;
		}
		kfree(buf);
	}

	/* Parse patch_x0_vals */
	if (patch_x0_vals[0] != '\0') {
		buf = kstrdup(patch_x0_vals, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		p = buf;
		i = 0;
		while ((tok = strsep(&p, ",")) != NULL && i < num_targets) {
			if (tok[0] == '\0')
				continue;
			targets[i].patch_x0 = simple_strtoull(tok, NULL, 0);
			i++;
		}
		kfree(buf);
	}

	/* Parse patch_pc_vals */
	if (patch_pc_vals[0] != '\0') {
		buf = kstrdup(patch_pc_vals, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		p = buf;
		i = 0;
		while ((tok = strsep(&p, ",")) != NULL && i < num_targets) {
			if (tok[0] == '\0')
				continue;
			targets[i].patch_pc = simple_strtoull(tok, NULL, 0);
			i++;
		}
		kfree(buf);
	}

parse_dump_regs:
	if (dump_regs[0] != '\0') {
		buf = kstrdup(dump_regs, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		p = buf;
		i = 0;
		while ((tok = strsep(&p, ",")) != NULL && i < num_targets) {
			int reg;
			if (tok[0] == '\0')
				continue;
			reg = (int)simple_strtol(tok, NULL, 0);
			if (reg >= 0 && reg <= 7)
				targets[i].dump_reg = reg;
			i++;
		}
		kfree(buf);
	}

	if (trigger_map[0] != '\0') {
		buf = kstrdup(trigger_map, GFP_KERNEL);
		if (!buf)
			return -ENOMEM;
		p = buf;
		i = 0;
		while ((tok = strsep(&p, ",")) != NULL && i < num_targets) {
			int trig;
			if (tok[0] == '\0')
				continue;
			trig = (int)simple_strtol(tok, NULL, 0);
			if (trig >= -1 && trig < num_targets && trig != i)
				targets[i].trigger_idx = trig;
			i++;
		}
		kfree(buf);
	}

	for (i = 0; i < num_targets; i++) {
		pr_info("hypsniff: target[%d] off=0x%lx type=%s trigger=%d dump_x%d\n",
			i, targets[i].lib_offset,
			targets[i].type == TARGET_TYPE_DATA ? "data" : "exec",
			targets[i].trigger_idx,
			targets[i].dump_reg);
	}
	return 0;
}

/* ===================== /proc/hypsniff ===================== */

static int hypsniff_show(struct seq_file *m, void *v)
{
	int i, n, idx;

	/* Invalidate dcache for shared data — EL2 writes non-cacheable */
	if (shared)
		flush_dcache_range(shared, 2 * PAGE_SIZE);

	seq_printf(m, "hypsniff pid=%d targets=%d captures=%u s2=%d sync=%u perm=%u one_shot=%d\n",
		   watched_pid, num_targets,
		   shared ? shared->cap_count : 0,
		   s2_enabled,
		   shared ? shared->dbg_sync_count : 0,
		   shared ? shared->dbg_perm_count : 0,
		   one_shot);

	for (i = 0; i < num_targets; i++) {
		struct hyp_target_desc *td = &hyp_targets[i];
		seq_printf(m, "  target[%d]: off=0x%lx type=%s action=%s armed=%u captured=%d ipa=0x%llx",
			   i, targets[i].lib_offset,
			   td->type == TARGET_TYPE_DATA ? "DATA" : "EXEC",
			   td->action == PATCH_ACTION_SKIP ? "skip" :
			   td->action == PATCH_ACTION_PATCH ? "patch" : "capture",
			   td->armed, targets[i].captured, td->ipa);
		if (targets[i].dump_reg >= 0) {
			seq_printf(m, " dump_x%d=%s(%ld)",
				   targets[i].dump_reg,
				   targets[i].dump_done ? "OK" : "pending",
				   targets[i].dump_bytes);
		}
		seq_printf(m, "\n");
	}

	if (!shared)
		return 0;

	n = shared->cap_count;
	if (n > MAX_HYP_CAPTURES)
		n = MAX_HYP_CAPTURES;

	for (i = 0; i < n; i++) {
		struct hyp_capture_entry *e;
		idx = (shared->cap_idx - n + i) & (MAX_HYP_CAPTURES - 1);
		e = &cap_entries[idx];

		seq_printf(m, "\n--- capture %d (t=%llu target=%d type=%s) ---\n",
			   i, e->timestamp, e->target_id,
			   e->cap_type ? "DATA_WRITE" : "EXEC");
		seq_printf(m, "pc=0x%016llx sp=0x%016llx\n", e->pc, e->sp);
		seq_printf(m, "x0=0x%016llx x1=0x%016llx\n", e->regs[0], e->regs[1]);
		seq_printf(m, "x2=0x%016llx x3=0x%016llx\n", e->regs[2], e->regs[3]);
		seq_printf(m, "x4=0x%016llx x5=0x%016llx\n", e->regs[4], e->regs[5]);
		seq_printf(m, "x6=0x%016llx x7=0x%016llx\n", e->regs[6], e->regs[7]);

		if (e->cap_type == 1) {
			seq_printf(m, "far=0x%016llx write_val=0x%016llx size=%u\n",
				   e->far, e->write_val, e->write_size);
		}
	}
	return 0;
}

static int hypsniff_open(struct inode *inode, struct file *file)
{
	return single_open(file, hypsniff_show, NULL);
}

static const struct file_operations hypsniff_fops = {
	.owner   = THIS_MODULE,
	.open    = hypsniff_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

/* /proc/hypsniff_dump — binary dump data, read with cat or dd */
static ssize_t dump_read(struct file *file, char __user *buf,
			  size_t count, loff_t *ppos)
{
	if (!dump_buf || dump_buf_len == 0)
		return 0;
	if (*ppos >= dump_buf_len)
		return 0;
	if (*ppos + count > dump_buf_len)
		count = dump_buf_len - *ppos;
	if (copy_to_user(buf, dump_buf + *ppos, count))
		return -EFAULT;
	*ppos += count;
	return count;
}

static const struct file_operations dump_fops = {
	.owner = THIS_MODULE,
	.read  = dump_read,
};

/* ===================== VA -> PA resolution (pagemap) ===================== */

static phys_addr_t resolve_user_pa(int pid, unsigned long va)
{
	char path[64];
	struct file *f;
	u64 entry = 0;
	loff_t offset;
	int ret;

	snprintf(path, sizeof(path), "/proc/%d/pagemap", pid);
	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f))
		return 0;

	offset = (va / PAGE_SIZE) * 8;
	ret = kernel_read(f, (char *)&entry, 8, &offset);
	filp_close(f, NULL);

	if (ret != 8)
		return 0;
	if (!(entry & (1ULL << 63)))
		return 0;

	return ((entry & ((1ULL << 55) - 1)) << PAGE_SHIFT) | (va & ~PAGE_MASK);
}

/* ===================== Library VA finder ===================== */

static int find_lib_va(int pid, const char *lname, unsigned long foff,
		       unsigned long *out_va)
{
	struct file *f;
	char path[64];
	char *buf;
	int total = 0, n, found_lib = 0;
	loff_t pos = 0;
	char *line, *end, *p;
	static int debug_once = 1;

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(f)) {
		if (debug_once) {
			pr_err("hypsniff: cannot open %s (err %ld)\n",
			       path, PTR_ERR(f));
			debug_once = 0;
		}
		return -1;
	}

	buf = kmalloc(KSYM_BUF_SIZE, GFP_KERNEL);
	if (!buf) {
		filp_close(f, NULL);
		return -1;
	}

	while (total < KSYM_BUF_SIZE - 1) {
		n = kernel_read(f, buf + total, KSYM_BUF_SIZE - 1 - total, &pos);
		if (n <= 0)
			break;
		total += n;
	}
	filp_close(f, NULL);

	if (debug_once && total < 100) {
		pr_warn("hypsniff: maps for PID %d only %d bytes (too small?)\n",
			pid, total);
	}

	buf[total] = 0;
	*out_va = 0;
	line = buf;
	while (line < buf + total) {
		end = strchr(line, '\n');
		if (end)
			*end = 0;
		else
			end = buf + total;

		if (strstr(line, lname)) {
			found_lib = 1;
			if (strstr(line, "r-xp") || strstr(line, "r--p") ||
			    strstr(line, "rwxp")) {
				unsigned long seg_start = 0, seg_end = 0, seg_foff = 0;

				seg_start = simple_strtoul(line, &p, 16);
				if (*p == '-')
					seg_end = simple_strtoul(p + 1, &p, 16);
				while (*p == ' ') p++;
				while (*p && *p != ' ') p++;
				while (*p == ' ') p++;
				seg_foff = simple_strtoul(p, NULL, 16);

				if (foff >= seg_foff &&
				    foff < seg_foff + (seg_end - seg_start)) {
					*out_va = seg_start + (foff - seg_foff);
					if (debug_once) {
						pr_info("hypsniff: %s found in PID %d: seg 0x%lx-0x%lx foff=0x%lx -> VA=0x%lx\n",
							lname, pid, seg_start, seg_end, seg_foff, *out_va);
						debug_once = 0;
					}
					break;
				}
			}
		}
		line = end + 1;
	}

	if (debug_once && found_lib && *out_va == 0) {
		pr_warn("hypsniff: %s found in maps but offset 0x%lx not in any segment\n",
			lname, foff);
	}
	if (debug_once && !found_lib && total > 1000) {
		pr_warn("hypsniff: %s NOT in maps (%d bytes read, PID %d)\n",
			lname, total, pid);
	}

	kfree(buf);
	return (*out_va != 0) ? 0 : -1;
}

/* ===================== HVC wrappers ===================== */

static void issue_hvc_set_vectors(void *pa_ptr)
{
	phys_addr_t pa = *(phys_addr_t *)pa_ptr;
	if (kfn_hyp_set_vectors)
		kfn_hyp_set_vectors(pa);
}

static void issue_hvc_init(void *data)
{
	int cpu;
	u64 vtcr = shared->vtcr_val;
	u64 vttbr = shared->vttbr_val;
	u64 stack_top;

	asm volatile("mrs %0, tpidr_el1" : "=r"(cpu));
	cpu &= 0xF;
	if (cpu >= NR_CPUS_MAX)
		cpu = 0;

	stack_top = stack_pas[cpu] + PAGE_SIZE;

	asm volatile(
		"mov x0, %[code]\n"
		"mov x1, %[vtcr]\n"
		"mov x2, %[vttbr]\n"
		"mov x3, %[stack]\n"
		"hvc #0\n"
		:
		: [code] "r" ((u64)HYPSNIFF_HVC_INIT),
		  [vtcr] "r" (vtcr),
		  [vttbr] "r" (vttbr),
		  [stack] "r" (stack_top)
		: "x0", "x1", "x2", "x3", "memory"
	);
}

static void issue_hvc_tlbi(unsigned long ipa)
{
	asm volatile(
		"mov x0, %[code]\n"
		"mov x1, %[ipa]\n"
		"hvc #0\n"
		:
		: [code] "r" ((u64)HYPSNIFF_HVC_TLBI),
		  [ipa] "r" ((u64)ipa)
		: "x0", "x1", "memory"
	);
}

static void issue_hvc_fini(void *data)
{
	asm volatile(
		"mov x0, %[code]\n"
		"hvc #0\n"
		:
		: [code] "r" ((u64)HYPSNIFF_HVC_FINI)
		: "x0", "memory"
	);
}

static void issue_hvc_set_shared(void *pa_ptr)
{
	u64 pa = *(u64 *)pa_ptr;
	asm volatile(
		"mov x0, %[code]\n"
		"mov x1, %[pa]\n"
		"hvc #0\n"
		:
		: [code] "r" ((u64)HYPSNIFF_HVC_SET_SHARED),
		  [pa] "r" (pa)
		: "x0", "x1", "memory"
	);
}

/* ===================== Arm / Disarm per target ===================== */

static int hyp_arm_target(int idx)
{
	struct target_config *tc = &targets[idx];
	struct hyp_target_desc *td = &hyp_targets[idx];
	phys_addr_t pa;
	int ret, i;

	pa = resolve_user_pa(watched_pid, tc->va);
	if (!pa) {
		pr_err("hypsniff: target[%d] VA 0x%lx -> PA failed\n",
		       idx, tc->va);
		return -EFAULT;
	}

	tc->pa = pa;
	pr_info("hypsniff: target[%d] VA 0x%lx -> PA 0x%llx\n",
		idx, tc->va, (u64)pa);

	ret = hyp_s2_drill_down_target(&s2, pa & PAGE_MASK, &tc->pte_pa);
	if (ret)
		return ret;

	td->ipa = pa & PAGE_MASK;
	td->pte_pa = tc->pte_pa;
	td->type = tc->type;
	td->action = tc->action;
	td->patch_mask = 0;

	if (tc->action == PATCH_ACTION_SKIP || tc->action == PATCH_ACTION_PATCH) {
		td->patch_x0 = tc->patch_x0;
		td->patch_pc = tc->patch_pc;

		/* For SKIP with patch_pc=0: auto-compute ret at VA-4 */
		if (tc->action == PATCH_ACTION_SKIP && td->patch_pc == 0 && tc->va >= 4) {
			td->patch_pc = tc->va - 4;
			pr_info("hypsniff: target[%d] SKIP auto-ret at VA 0x%llx\n",
				idx, td->patch_pc);
		}

		if (tc->patch_x0 || tc->action == PATCH_ACTION_SKIP)
			td->patch_mask |= (1 << 0);
		if (td->patch_pc)
			td->patch_mask |= (1 << 8);
	}

	if (tc->type == TARGET_TYPE_EXEC)
		hyp_s2_set_xn_at(&s2, tc->pte_pa);
	else
		hyp_s2_set_ro_at(&s2, tc->pte_pa);

	td->armed = 1;
	tc->armed = 1;

	shared->num_targets = num_targets;
	flush_dcache_range(hyp_targets, PAGE_SIZE);
	flush_dcache_range(shared, 2 * PAGE_SIZE);

	/* Enable S2 on ALL CPUs right before arming — minimizes fault window */
	if (!s2_enabled) {
		/* Flush ALL page table data before enabling S2 */
		flush_dcache_range(s2.l1, 2 * PAGE_SIZE);
		for (i = 0; i < s2.num_l2; i++)
			flush_dcache_range(s2.l2[i].va, PAGE_SIZE);
		for (i = 0; i < s2.num_l3; i++)
			flush_dcache_range(s2.l3[i].va, PAGE_SIZE);

		kfn_on_each_cpu(issue_hvc_init, NULL, 1);
		s2_enabled = 1;

		/* Full TLB invalidate on all CPUs after enabling S2 */
		issue_hvc_tlbi(0);
		pr_info("hypsniff: stage-2 ENABLED on all CPUs (just-in-time)\n");
	} else {
		issue_hvc_init(NULL);
	}
	issue_hvc_tlbi(pa & PAGE_MASK);

	pr_info("hypsniff: armed target[%d] type=%s action=%s PA 0x%llx\n",
		idx,
		tc->type == TARGET_TYPE_DATA ? "data" : "exec",
		tc->action == PATCH_ACTION_SKIP ? "skip" :
		tc->action == PATCH_ACTION_PATCH ? "patch" : "capture",
		(u64)pa);
	return 0;
}

static void hyp_disarm_target(int idx)
{
	struct target_config *tc = &targets[idx];
	struct hyp_target_desc *td = &hyp_targets[idx];

	if (!tc->armed && !td->armed)
		return;

	if (tc->type == TARGET_TYPE_EXEC)
		hyp_s2_clear_xn_at(&s2, tc->pte_pa);
	else
		hyp_s2_clear_ro_at(&s2, tc->pte_pa);

	td->armed = 0;
	tc->armed = 0;

	if (td->ipa)
		issue_hvc_tlbi(td->ipa);
}

static void hyp_disarm_all(void)
{
	int i;
	for (i = 0; i < num_targets; i++)
		hyp_disarm_target(i);
}

/* ===================== Memory dump on capture ===================== */

static int find_capture_for_target(int target_idx)
{
	int i, n, idx;

	if (!shared)
		return -1;

	flush_dcache_range(shared, 2 * PAGE_SIZE);

	n = shared->cap_count;
	if (n > MAX_HYP_CAPTURES)
		n = MAX_HYP_CAPTURES;

	for (i = n - 1; i >= 0; i--) {
		idx = (shared->cap_idx - n + i) & (MAX_HYP_CAPTURES - 1);
		if (cap_entries[idx].target_id == target_idx)
			return idx;
	}
	return -1;
}

static long dump_capture_memory(int pid, int target_idx)
{
	struct target_config *tc = &targets[target_idx];
	struct hyp_capture_entry *e;
	int cap_idx;
	u64 ptr;
	struct file *mem_f;
	char path[64];
	long total = 0;
	loff_t pos;
	long to_read;
	int n;

	if (tc->dump_reg < 0 || tc->dump_reg > 7)
		return -EINVAL;

	cap_idx = find_capture_for_target(target_idx);
	if (cap_idx < 0)
		return -ENOENT;

	e = &cap_entries[cap_idx];
	ptr = e->regs[tc->dump_reg];

	if (!ptr || ptr < 0x1000) {
		pr_warn("hypsniff: target[%d] x%d=0x%llx — invalid pointer\n",
			target_idx, tc->dump_reg, ptr);
		return -EFAULT;
	}

	to_read = (long)dump_size;
	if (to_read > MAX_DUMP_SIZE)
		to_read = MAX_DUMP_SIZE;

	pr_info("hypsniff: dumping target[%d] x%d=0x%llx (%ld bytes) to /proc/hypsniff_dump...\n",
		target_idx, tc->dump_reg, ptr, to_read);

	snprintf(path, sizeof(path), "/proc/%d/mem", pid);
	mem_f = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(mem_f)) {
		pr_err("hypsniff: cannot open %s: %ld\n", path, PTR_ERR(mem_f));
		return PTR_ERR(mem_f);
	}

	if (!dump_buf) {
		dump_buf = kmalloc(MAX_DUMP_SIZE, GFP_KERNEL);
		if (!dump_buf) {
			filp_close(mem_f, NULL);
			return -ENOMEM;
		}
	}

	pos = ptr;
	while (total < to_read) {
		long chunk = to_read - total;
		if (chunk > PAGE_SIZE)
			chunk = PAGE_SIZE;

		n = kernel_read(mem_f, dump_buf + total, chunk, &pos);
		if (n <= 0)
			break;
		total += n;
	}

	filp_close(mem_f, NULL);

	dump_buf_len = total;
	tc->dump_done = 1;
	tc->dump_bytes = total;

	pr_info("hypsniff: dumped %ld bytes — read via: cat /proc/hypsniff_dump > /sdcard/dump.bin\n",
		total);
	return total;
}

/* ===================== Watcher thread ===================== */

static int watcher_fn(void *data)
{
	struct task_struct *p;
	int found_pid;
	unsigned long va;
	int i, retry, all_found;

	while (!kthread_should_stop()) {
		/* Phase 1: Find target process */
		if (!watched_pid) {
			found_pid = 0;
			rcu_read_lock();
			for_each_process(p) {
				if (strstr(p->comm, watch_name)) {
					found_pid = p->tgid;
					break;
				}
			}
			rcu_read_unlock();

			if (!found_pid) {
				msleep(100);
				continue;
			}

			pr_info("hypsniff: found PID %d, waiting for lib...\n", found_pid);
			watched_pid = found_pid;

			/* Retry VA resolution until process dies or thread stops */
			for (retry = 0; ; retry++) {
				all_found = 1;
				for (i = 0; i < num_targets; i++) {
					if (targets[i].va)
						continue;
					if (find_lib_va(found_pid, lib_name,
							targets[i].lib_offset, &va) == 0 && va) {
						targets[i].va = va;
						pr_info("hypsniff: target[%d] off=0x%lx -> VA=0x%lx\n",
							i, targets[i].lib_offset, va);
					} else {
						all_found = 0;
					}
				}
				if (all_found)
					break;
				msleep(500);

				if (kthread_should_stop())
					break;

				/* Check process still alive */
				rcu_read_lock();
				p = pid_task(find_vpid(watched_pid), PIDTYPE_PID);
				rcu_read_unlock();
				if (!p) {
					pr_info("hypsniff: PID %d died during lib wait\n",
						watched_pid);
					watched_pid = 0;
					for (i = 0; i < num_targets; i++)
						targets[i].va = 0;
					break;
				}

				if (retry > 0 && (retry % 20) == 0)
					pr_info("hypsniff: still waiting for %s in PID %d (%d retries)...\n",
						lib_name, watched_pid, retry);
			}

			if (!watched_pid)
				continue;

			if (arm_delay_ms > 0) {
				pr_info("hypsniff: delaying arm by %lu ms (letting app settle)...\n",
					arm_delay_ms);
				msleep(arm_delay_ms);

				rcu_read_lock();
				p = pid_task(find_vpid(watched_pid), PIDTYPE_PID);
				rcu_read_unlock();
				if (!p) {
					pr_info("hypsniff: PID %d died during arm delay\n",
						watched_pid);
					watched_pid = 0;
					for (i = 0; i < num_targets; i++)
						targets[i].va = 0;
					continue;
				}
			}

			for (i = 0; i < num_targets; i++) {
				if (!targets[i].va) {
					pr_err("hypsniff: target[%d] off=0x%lx -> VA NOT FOUND\n",
					       i, targets[i].lib_offset);
					continue;
				}
				if (targets[i].trigger_idx >= 0) {
					pr_info("hypsniff: target[%d] DEFERRED — waiting for target[%d] trigger\n",
						i, targets[i].trigger_idx);
					continue;
				}
				if (hyp_arm_target(i) != 0)
					pr_err("hypsniff: failed to arm target[%d]\n", i);
			}

			msleep(200);
			continue;
		}

		/* Phase 2: Monitor + re-arm (or one-shot capture + dump) */
		rcu_read_lock();
		p = pid_task(find_vpid(watched_pid), PIDTYPE_PID);
		rcu_read_unlock();
		if (!p) {
			pr_info("hypsniff: PID %d died\n", watched_pid);
			hyp_disarm_all();
			watched_pid = 0;
			for (i = 0; i < num_targets; i++) {
				targets[i].va = 0;
				targets[i].armed = 0;
				targets[i].captured = 0;
				targets[i].dump_done = 0;
				targets[i].dump_bytes = 0;
			}
			if (!s2_enabled) {
				pr_info("hypsniff: re-enabling stage-2 for next process\n");
				kfn_on_each_cpu(issue_hvc_init, NULL, 1);
				s2_enabled = 1;
			}
			msleep(100);
			continue;
		}

		/* Invalidate dcache — EL2 writes non-cacheable to DRAM */
		flush_dcache_range(shared, PAGE_SIZE);

		{
			int all_captured = 1;
			int any_still_armed = 0;

			for (i = 0; i < num_targets; i++) {
				if (!targets[i].va)
					continue;

				if (!hyp_targets[i].armed && targets[i].armed) {
					/* EL2 disarmed this target — a capture happened */
					targets[i].armed = 0;
				}

				/* Check for capture: trigger targets accept ANY page hit,
				 * payload targets require exact PC match */
				if (one_shot && !targets[i].captured && targets[i].va) {
					int is_trigger = 0;
					int ci, cn, cidx, j;

					/* Is this target a trigger for something else? */
					for (j = 0; j < num_targets; j++) {
						if (targets[j].trigger_idx == i) {
							is_trigger = 1;
							break;
						}
					}

					flush_dcache_range(shared, 2 * PAGE_SIZE);
					cn = shared->cap_count;
					if (cn > MAX_HYP_CAPTURES)
						cn = MAX_HYP_CAPTURES;

					for (ci = 0; ci < cn; ci++) {
						cidx = (shared->cap_idx - cn + ci) & (MAX_HYP_CAPTURES - 1);
						if (cap_entries[cidx].target_id != i)
							continue;

						/* Trigger targets: accept ANY capture on the page */
						/* Payload targets: require exact PC match */
						if (is_trigger || cap_entries[cidx].pc == targets[i].va) {
							targets[i].captured = 1;
							pr_info("hypsniff: target[%d] %s PC 0x%llx in capture %d!\n",
								i,
								is_trigger ? "TRIGGER (any page hit)" : "MATCHED",
								cap_entries[cidx].pc, ci);

							if (targets[i].dump_reg >= 0 && !targets[i].dump_done)
								dump_capture_memory(watched_pid, i);

							/* Arm any targets that were waiting for this trigger */
							{
								int j;
								for (j = 0; j < num_targets; j++) {
									if (targets[j].trigger_idx == i &&
									    !targets[j].armed && !targets[j].captured &&
									    targets[j].va) {
										pr_info("hypsniff: TRIGGER fired — arming target[%d]\n", j);
										if (hyp_arm_target(j) != 0)
											pr_err("hypsniff: failed to arm triggered target[%d]\n", j);
									}
								}
							}
							break;
						}
					}
				}

				if (one_shot && targets[i].captured) {
					/* Already captured — don't re-arm */
				} else if (targets[i].trigger_idx >= 0 &&
					   !targets[targets[i].trigger_idx].captured) {
					/* Trigger hasn't fired — don't arm yet */
				} else if (!hyp_targets[i].armed && targets[i].va) {
					/* Re-arm (legacy behavior when one_shot=0) */
					msleep(50);
					if (targets[i].type == TARGET_TYPE_EXEC)
						hyp_s2_set_xn_at(&s2, targets[i].pte_pa);
					else
						hyp_s2_set_ro_at(&s2, targets[i].pte_pa);
					flush_dcache_range(&hyp_targets[i],
							   sizeof(struct hyp_target_desc));
					hyp_targets[i].armed = 1;
					targets[i].armed = 1;
					issue_hvc_tlbi(hyp_targets[i].ipa);
					any_still_armed = 1;
				}

				if (hyp_targets[i].armed)
					any_still_armed = 1;

				if (!targets[i].captured)
					all_captured = 0;
			}

			if (one_shot && all_captured && s2_enabled) {
				pr_info("hypsniff: ALL targets captured — disabling stage-2\n");
				kfn_on_each_cpu(issue_hvc_fini, NULL, 1);
				s2_enabled = 0;
			} else if (any_still_armed || !one_shot) {
				/* Keep VM=1 alive on all CPUs — EL3 restores VM=0 on idle */
				kfn_on_each_cpu(issue_hvc_init, NULL, 1);
			}
		}

		msleep(200);
	}
	return 0;
}

/* ===================== Init / Exit ===================== */

static int alloc_stacks(void)
{
	int i;
	unsigned long pg;

	for (i = 0; i < NR_CPUS_MAX; i++) {
		pg = kfn_get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
		if (!pg)
			return -ENOMEM;
		stack_pages[i] = (void *)pg;
		stack_pas[i] = at_virt_to_phys(stack_pages[i]);
	}
	return 0;
}

static void free_stacks(void)
{
	int i;
	for (i = 0; i < NR_CPUS_MAX; i++) {
		if (stack_pages[i]) {
			kfn_free_pages((unsigned long)stack_pages[i], 0);
			stack_pages[i] = NULL;
		}
	}
}

static void write_stub_vectors(void *page)
{
	u32 *code = (u32 *)page;
	int i;
	for (i = 0; i < 16; i++)
		code[i * (0x80 / sizeof(u32))] = 0xD69F03E0; /* eret */
}

/* Read /proc/hypsniff_vectors to get boot-installed vector page PA */
static unsigned long read_boot_vectors_pa(void)
{
	struct file *f;
	char buf[64];
	int n;
	loff_t pos = 0;
	unsigned long pa = 0;

	f = filp_open("/proc/hypsniff_vectors", O_RDONLY, 0);
	if (IS_ERR(f))
		return 0;

	n = kernel_read(f, buf, sizeof(buf) - 1, &pos);
	filp_close(f, NULL);

	if (n > 3) {
		char *p;
		buf[n] = 0;
		p = strstr(buf, "pa=0x");
		if (p)
			pa = simple_strtoul(p + 3, NULL, 16);
	}
	return pa;
}

static int setup_vectors(void)
{
	size_t vec_size;
	u64 *slot_va;
	char *src, *dst;
	size_t j;

	vec_size = hypsniff_vectors_end - hypsniff_vectors;
	if (vec_size > VECTORS_SIZE) {
		pr_err("hypsniff: vectors too large: %zu > %d\n",
		       vec_size, VECTORS_SIZE);
		return -E2BIG;
	}

	if (custom_uh_pa) {
		pr_info("hypsniff: custom UH mode — vectors already at PA 0x%lx\n",
			custom_uh_pa);
		vector_page_pa = custom_uh_pa;
		vector_page = NULL;  /* Can't write to UH memory from EL1 */
		/* shared_pa will be set via HVC_SET_SHARED instead */
		pr_info("hypsniff: will use HVC to set shared_pa at runtime\n");
		return 0;
	} else {
		/* Try boot-installed vectors (Exynos SMC bootstrap) */
		vector_page_pa = read_boot_vectors_pa();
		if (vector_page_pa) {
			pr_info("hypsniff: using boot-installed vectors at PA 0x%llx\n",
				(u64)vector_page_pa);
			vector_page = phys_to_virt(vector_page_pa);
			if (!vector_page) {
				pr_err("hypsniff: phys_to_virt failed for 0x%llx\n",
				       (u64)vector_page_pa);
				return -EFAULT;
			}
		} else {
			unsigned long pg;

			pr_info("hypsniff: no boot vectors, allocating fresh page\n");
			pg = kfn_get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
			if (!pg)
				return -ENOMEM;
			vector_page = (void *)pg;
			vector_page_pa = at_virt_to_phys(vector_page);
		}
	}

	/* Copy our vectors into the page (overwriting boot stubs if present) */
	dst = (char *)vector_page;
	src = hypsniff_vectors;
	for (j = 0; j < vec_size; j++)
		dst[j] = src[j];

	/* Write shared_data PA at offset 0x800 */
	slot_va = (u64 *)((char *)vector_page + 0x800);
	*slot_va = shared_pa;

	flush_dcache_range(vector_page, PAGE_SIZE);

	pr_info("hypsniff: vectors at PA 0x%llx, shared at PA 0x%llx\n",
		(u64)vector_page_pa, (u64)shared_pa);
	return 0;
}

static int hypsniff_init(void)
{
	int ret;
	unsigned long sym;
	unsigned long pg;

	pr_info("hypsniff: loading v2 (watch=%s lib=%s)\n", watch_name, lib_name);

	ret = parse_target_params();
	if (ret)
		return ret;

	boot_vectors = read_boot_vectors_pa() ? 1 : 0;
	pr_info("hypsniff: boot vectors: %s\n", boot_vectors ? "YES" : "NO");

	/* Read SMC result from boot init (for debugging) */
	sym = resolve_ksym("hypsniff_el2_smc_result");
	if (sym) {
		long *smc_result = (long *)sym;
		pr_info("hypsniff: boot SMC result: %ld (0x%lx)\n",
			*smc_result, *smc_result);
	}

	sym = resolve_ksym("__hyp_set_vectors");
	kfn_hyp_set_vectors = sym ? (hyp_set_vectors_fn)sym : NULL;

	sym = resolve_ksym("on_each_cpu");
	if (!sym) {
		pr_err("hypsniff: cannot find on_each_cpu\n");
		return -ENOENT;
	}
	kfn_on_each_cpu = (on_each_cpu_fn)sym;

	sym = resolve_ksym("__get_free_pages");
	if (!sym) {
		pr_err("hypsniff: cannot find __get_free_pages\n");
		return -ENOENT;
	}
	kfn_get_free_pages = (get_free_pages_fn)sym;

	sym = resolve_ksym("free_pages");
	if (!sym) {
		pr_err("hypsniff: cannot find free_pages\n");
		return -ENOENT;
	}
	kfn_free_pages = (free_pages_fn)sym;

	sym = resolve_ksym("__hyp_stub_vectors");
	if (sym) {
		orig_vectors_pa = at_virt_to_phys((void *)sym);
		pr_info("hypsniff: original vectors at PA 0x%llx\n", (u64)orig_vectors_pa);
	}

	/* Allocate 2 pages: page 0 = shared_data, page 1 = capture entries */
	pg = kfn_get_free_pages(GFP_KERNEL | __GFP_ZERO, 1);
	if (!pg)
		return -ENOMEM;
	shared = (struct hyp_shared_data *)pg;
	cap_entries = (struct hyp_capture_entry *)(pg + PAGE_SIZE);
	shared_pa = at_virt_to_phys(shared);

	/* Allocate target descriptors (visible to EL2) */
	pg = kfn_get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
	if (!pg) {
		kfn_free_pages((unsigned long)shared, 1);
		return -ENOMEM;
	}
	hyp_targets = (struct hyp_target_desc *)pg;

	shared->cap_buf_pa = shared_pa + PAGE_SIZE;
	shared->cap_max = MAX_HYP_CAPTURES;
	shared->orig_vectors_pa = orig_vectors_pa;
	shared->targets_base_pa = at_virt_to_phys(hyp_targets);

	ret = hyp_s2_build(&s2);
	if (ret)
		goto fail_s2;

	shared->vtcr_val = (1UL << 31) |	/* RES1 */
			   24          |	/* T0SZ = 24 (40-bit IPA) */
			   (1UL << 6)  |	/* SL0 = 1 (start at L1) */
			   (3UL << 8)  |	/* IRGN0 = WB WA */
			   (3UL << 10) |	/* ORGN0 = WB WA */
			   (3UL << 12) |	/* SH0 = Inner Shareable */
			   (2UL << 16);		/* PS = 40-bit */
	shared->vttbr_val = s2.l1_pa;

	ret = alloc_stacks();
	if (ret)
		goto fail_stacks;

	ret = setup_vectors();
	if (ret)
		goto fail_vectors;

	if (custom_uh_pa) {
		pr_info("hypsniff: custom UH — setting shared_pa via HVC\n");
		issue_hvc_set_shared(&shared_pa);
		pr_info("hypsniff: shared_pa 0x%llx sent to EL2\n", (u64)shared_pa);
	} else if (boot_vectors) {
		pr_info("hypsniff: boot vectors active — code overwritten at PA 0x%llx\n",
			(u64)vector_page_pa);
	} else {
		pr_warn("hypsniff: using HVC set_vectors (may fail on Exynos)\n");
		kfn_on_each_cpu(issue_hvc_set_vectors, &vector_page_pa, 1);
	}
	vectors_installed = 1;
	pr_info("hypsniff: vectors installed on all CPUs\n");

	if (pre_arm_pa) {
		/* Pre-arm: drill and set XN BEFORE BSRE starts.
		 * Use PA from a previous run to eliminate the VA-resolution race. */
		phys_addr_t pte_pa;
		ret = hyp_s2_drill_down_target(&s2, pre_arm_pa & PAGE_MASK, &pte_pa);
		if (ret == 0) {
			targets[0].pa = pre_arm_pa;
			targets[0].pte_pa = pte_pa;

			hyp_targets[0].ipa = pre_arm_pa & PAGE_MASK;
			hyp_targets[0].pte_pa = pte_pa;
			hyp_targets[0].type = targets[0].type;
			hyp_targets[0].action = targets[0].action;
			hyp_targets[0].patch_mask = 0;
			hyp_targets[0].armed = 1;
			targets[0].armed = 1;
			shared->num_targets = num_targets;

			flush_dcache_range(hyp_targets, PAGE_SIZE);
			flush_dcache_range(shared, 2 * PAGE_SIZE);

			hyp_s2_set_xn_at(&s2, pte_pa);

			kfn_on_each_cpu(issue_hvc_init, NULL, 1);
			s2_enabled = 1;
			issue_hvc_tlbi(pre_arm_pa & PAGE_MASK);

			pr_info("hypsniff: PRE-ARMED at PA 0x%lx — XN set BEFORE app starts\n",
				pre_arm_pa);
		} else {
			pr_err("hypsniff: pre-arm drill failed: %d\n", ret);
		}
	} else {
		/* DON'T enable stage-2 yet — wait until watcher is ready to arm. */
		pr_info("hypsniff: stage-2 DEFERRED — will enable at arm time\n");
	}

	proc_entry = proc_create("hypsniff", 0444, NULL, &hypsniff_fops);
	if (!proc_entry) {
		ret = -ENOMEM;
		goto fail_proc;
	}

	proc_dump_entry = proc_create("hypsniff_dump", 0444, NULL, &dump_fops);
	if (!proc_dump_entry)
		pr_warn("hypsniff: could not create /proc/hypsniff_dump\n");

	if (watch_name && watch_name[0]) {
		watcher_thread = kthread_run(watcher_fn, NULL, "hypsniff_watch");
		if (IS_ERR(watcher_thread)) {
			ret = PTR_ERR(watcher_thread);
			watcher_thread = NULL;
			goto fail_watcher;
		}
	}

	pr_info("hypsniff: loaded successfully (%d targets)\n", num_targets);
	return 0;

fail_watcher:
	remove_proc_entry("hypsniff", NULL);
fail_proc:
	issue_hvc_fini(NULL);
	s2_enabled = 0;
	kfn_on_each_cpu(issue_hvc_set_vectors, &orig_vectors_pa, 1);
	vectors_installed = 0;
fail_vectors:
	if (custom_uh_pa) {
		/* phys_to_virt — nothing to free */
	} else if (vector_page)
		kfn_free_pages((unsigned long)vector_page, 0);
fail_stacks:
	free_stacks();
fail_s2:
	hyp_s2_free(&s2);
	if (shared)
		kfn_free_pages((unsigned long)shared, 1);
	return ret;
}

static void hypsniff_exit(void)
{
	pr_info("hypsniff: unloading (%u captures)\n",
		shared ? shared->cap_count : 0);

	if (watcher_thread)
		kthread_stop(watcher_thread);

	hyp_disarm_all();

	if (proc_dump_entry)
		remove_proc_entry("hypsniff_dump", NULL);
	if (proc_entry)
		remove_proc_entry("hypsniff", NULL);

	if (s2_enabled) {
		issue_hvc_fini(NULL);
		s2_enabled = 0;
	}

	if (custom_uh_pa) {
		pr_info("hypsniff: custom UH — vectors stay in UH partition\n");
	} else if (vectors_installed && !boot_vectors) {
		kfn_on_each_cpu(issue_hvc_set_vectors, &orig_vectors_pa, 1);
		vectors_installed = 0;
		if (vector_page)
			kfn_free_pages((unsigned long)vector_page, 0);
	} else if (boot_vectors && vector_page) {
		char *dst = (char *)vector_page;
		size_t j;
		for (j = 0; j < PAGE_SIZE; j++)
			dst[j] = 0;
		write_stub_vectors(vector_page);
		flush_dcache_range(vector_page, PAGE_SIZE);
		pr_info("hypsniff: restored eret stubs to boot vector page\n");
	} else if (vector_page) {
		kfn_free_pages((unsigned long)vector_page, 0);
	}

	free_stacks();
	hyp_s2_free(&s2);

	if (dump_buf)
		kfree(dump_buf);
	if (hyp_targets)
		kfn_free_pages((unsigned long)hyp_targets, 0);
	if (shared)
		kfn_free_pages((unsigned long)shared, 1);

	pr_info("hypsniff: unloaded\n");
}

module_init(hypsniff_init);
module_exit(hypsniff_exit);
