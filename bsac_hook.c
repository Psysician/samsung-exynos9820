/*
 * bsac_hook.c - Kernel module to intercept process termination syscalls
 *
 * Target: Samsung SM-G973F (Exynos 9820, arm64)
 * Kernel: CruelKernel 4.14.113
 *
 * Hooks exit_group(94), kill(129), tgkill(131) on arm64.
 * Suppresses termination when the affected process comm contains "brawlstar".
 *
 * Build:
 *   make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KERNEL_DIR=/path/to/kernel
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
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bsac");
MODULE_DESCRIPTION("Syscall hook to prevent process termination");
MODULE_VERSION("1.0");

/* arm64 syscall numbers */
#define __NR_exit_group_arm64  94
#define __NR_kill_arm64       129
#define __NR_tgkill_arm64     131

/* Comm substring to match */
#define TARGET_COMM "brawlstar"

/* Signals we suppress */
#define SIG_ABORT  SIGABRT  /* 6 */
#define SIG_KILL   SIGKILL  /* 9 */

static void **sys_call_table;

/* Original syscall function pointers */
typedef asmlinkage long (*syscall_fn_t)(const struct pt_regs *regs);

static syscall_fn_t orig_exit_group;
static syscall_fn_t orig_kill;
static syscall_fn_t orig_tgkill;

/* ------------------------------------------------------------------ */
/* arm64 page table manipulation for making sys_call_table writable    */
/* ------------------------------------------------------------------ */

/*
 * On arm64 kernel 4.14, sys_call_table lives in .rodata and is mapped
 * read-only.  set_memory_rw() does not reliably flip rodata pages on
 * all arm64 builds.  Instead we walk the kernel page tables, find the
 * PTE for the target address, clear PTE_RDONLY, and issue a TLB
 * invalidate.  We restore the original PTE attributes on unload.
 *
 * This is inherently arch-specific and kernel-version-specific.
 */

static struct mm_struct *kern_mm;

static pte_t *walk_page_table(unsigned long addr)
{
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;

	if (!kern_mm) {
		kern_mm = (struct mm_struct *)kallsyms_lookup_name("init_mm");
		if (!kern_mm) {
			pr_info("bsac_hook: init_mm not found via kallsyms\n");
			return NULL;
		}
	}

	pgdp = pgd_offset(kern_mm, addr);
	if (pgd_none(*pgdp) || pgd_bad(*pgdp))
		return NULL;

	pudp = pud_offset(pgdp, addr);
	if (pud_none(*pudp) || pud_bad(*pudp))
		return NULL;

	pmdp = pmd_offset(pudp, addr);

	/*
	 * If the PMD is a section mapping (1GB or 2MB block), we cannot
	 * get a PTE -- the entire block shares one set of attributes.
	 * On most Samsung/Cruel kernels the syscall table sits in a
	 * section-mapped region.  In that case we fall back to the
	 * SCTLR_EL1 WXN-clear approach below.
	 */
	if (pmd_none(*pmdp))
		return NULL;

#ifdef pmd_sect
	if (pmd_sect(*pmdp)) {
		pr_info("bsac_hook: PMD is section-mapped, PTE walk N/A\n");
		return NULL;
	}
#endif

	if (pmd_bad(*pmdp))
		return NULL;

	ptep = pte_offset_kernel(pmdp, addr);
	if (pte_none(*ptep))
		return NULL;

	return ptep;
}

static pte_t saved_pte;
static pte_t *target_ptep;
static int used_pte_method;

/*
 * Attempt 1: PTE-based write enable.
 * Walk the page tables and clear PTE_RDONLY on the page containing addr.
 */
static int try_pte_make_rw(unsigned long addr)
{
	pte_t pte;

	target_ptep = walk_page_table(addr);
	if (!target_ptep)
		return -1;

	saved_pte = *target_ptep;
	pte = pte_mkwrite(saved_pte);
	set_pte(target_ptep, pte);

	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
	return 0;
}

static void pte_restore_ro(unsigned long addr)
{
	if (target_ptep) {
		set_pte(target_ptep, saved_pte);
		flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
	}
}

/*
 * Attempt 2: Inline assembly to temporarily disable WP via SCTLR_EL1.
 * On arm64 bit 19 of SCTLR_EL1 is WXN (Write-implies-XN).  Clearing
 * it does not directly give us write to rodata, but we can also try
 * clearing bit 25 (EE) is irrelevant -- the actual trick on 4.14 arm64
 * is to disable the MMU write-protect by clearing SCTLR_EL1 bit 2 (C)
 * temporarily.
 *
 * A more portable approach: use update_mapping_prot() which is exported
 * on some Samsung kernels, or aarch64_insn_patch_text_nosync() for
 * word-sized writes.  We try those first.
 */

/* Kernel may export these -- resolved at runtime via kallsyms */
typedef void (*update_mapping_prot_fn)(phys_addr_t phys, unsigned long virt,
				       phys_addr_t size, pgprot_t prot);
typedef void (*set_memory_rw_fn)(unsigned long addr, int numpages);

static update_mapping_prot_fn fn_update_mapping_prot;
static set_memory_rw_fn fn_set_memory_rw;
static set_memory_rw_fn fn_set_memory_ro;

static unsigned long sct_phys;
static unsigned long sct_virt;
static int used_update_mapping;
static int used_set_memory;

static int try_update_mapping_rw(unsigned long addr)
{
	fn_update_mapping_prot = (update_mapping_prot_fn)
		kallsyms_lookup_name("update_mapping_prot");

	if (!fn_update_mapping_prot) {
		pr_info("bsac_hook: update_mapping_prot not found\n");
		return -1;
	}

	sct_virt = addr & PAGE_MASK;
	sct_phys = virt_to_phys((void *)sct_virt);

	fn_update_mapping_prot(sct_phys, sct_virt, PAGE_SIZE, PAGE_KERNEL);
	pr_info("bsac_hook: update_mapping_prot -> RW OK\n");
	return 0;
}

static void update_mapping_restore_ro(unsigned long addr)
{
	if (fn_update_mapping_prot) {
		fn_update_mapping_prot(sct_phys, sct_virt, PAGE_SIZE,
				       PAGE_KERNEL_RO);
	}
}

static int try_set_memory_rw_method(unsigned long addr)
{
	fn_set_memory_rw = (set_memory_rw_fn)
		kallsyms_lookup_name("set_memory_rw");
	fn_set_memory_ro = (set_memory_rw_fn)
		kallsyms_lookup_name("set_memory_ro");

	if (!fn_set_memory_rw || !fn_set_memory_ro) {
		pr_info("bsac_hook: set_memory_rw/ro not found\n");
		return -1;
	}

	fn_set_memory_rw(addr & PAGE_MASK, 1);
	pr_info("bsac_hook: set_memory_rw -> OK\n");
	return 0;
}

static void set_memory_restore_ro(unsigned long addr)
{
	if (fn_set_memory_ro)
		fn_set_memory_ro(addr & PAGE_MASK, 1);
}

/*
 * Attempt 3: Direct inline asm -- disable write protection at EL1.
 * This is the brute-force fallback.  We flip SCTLR_EL1 bit 19 (WXN)
 * off, do our writes, then restore it.  This must be done with
 * preemption and interrupts disabled.
 */
static unsigned long saved_sctlr;

static void arm64_disable_wp(void)
{
	unsigned long sctlr;

	asm volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
	saved_sctlr = sctlr;
	sctlr &= ~(1UL << 19); /* clear WXN */
	asm volatile(
		"msr sctlr_el1, %0\n"
		"isb\n"
		: : "r"(sctlr)
	);
}

static void arm64_restore_wp(void)
{
	asm volatile(
		"msr sctlr_el1, %0\n"
		"isb\n"
		: : "r"(saved_sctlr)
	);
}

/* Unified helpers that try each method in order */
static int make_sct_rw(unsigned long addr)
{
	/* Method 1: update_mapping_prot (Samsung/Cruel often exports this) */
	if (try_update_mapping_rw(addr) == 0) {
		used_update_mapping = 1;
		return 0;
	}

	/* Method 2: set_memory_rw */
	if (try_set_memory_rw_method(addr) == 0) {
		used_set_memory = 1;
		return 0;
	}

	/* Method 3: PTE walk */
	if (try_pte_make_rw(addr) == 0) {
		used_pte_method = 1;
		return 0;
	}

	/* Method 4: SCTLR_EL1 WXN disable (brute force) */
	pr_info("bsac_hook: falling back to SCTLR_EL1 WXN disable\n");
	preempt_disable();
	arm64_disable_wp();
	return 0;
}

static void make_sct_ro(unsigned long addr)
{
	if (used_update_mapping) {
		update_mapping_restore_ro(addr);
	} else if (used_set_memory) {
		set_memory_restore_ro(addr);
	} else if (used_pte_method) {
		pte_restore_ro(addr);
	} else {
		/* SCTLR fallback -- restore WP and re-enable preemption */
		arm64_restore_wp();
		preempt_enable();
	}
}

/* ------------------------------------------------------------------ */
/* Helper: check if a PID's comm matches the target                    */
/* ------------------------------------------------------------------ */

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

static bool is_target_current(void)
{
	return strstr(current->comm, TARGET_COMM) != NULL;
}

/* ------------------------------------------------------------------ */
/* Hooked syscall handlers                                             */
/* ------------------------------------------------------------------ */

/*
 * On arm64 kernel 4.14 with CONFIG_ARCH_HAS_SYSCALL_WRAPPER, syscall
 * functions take a single pt_regs pointer.  Arguments are extracted
 * from regs->regs[0..5].
 *
 *   exit_group(int status)        -> regs->regs[0] = status
 *   kill(pid_t pid, int sig)      -> regs->regs[0] = pid, regs->regs[1] = sig
 *   tgkill(pid_t tgid, pid_t tid, int sig) -> regs[0]=tgid, regs[1]=tid, regs[2]=sig
 */

static asmlinkage long hook_exit_group(const struct pt_regs *regs)
{
	if (is_target_current()) {
		pr_info("bsac_hook: blocked exit_group from %s (pid %d)\n",
			current->comm, current->pid);
		return 0;
	}
	return orig_exit_group(regs);
}

static asmlinkage long hook_kill(const struct pt_regs *regs)
{
	pid_t target_pid = (pid_t)regs->regs[0];
	int sig = (int)regs->regs[1];

	if ((sig == SIG_ABORT || sig == SIG_KILL) && is_target_pid(target_pid)) {
		pr_info("bsac_hook: blocked kill(%d, %d) targeting %s\n",
			target_pid, sig, TARGET_COMM);
		return 0;
	}
	return orig_kill(regs);
}

static asmlinkage long hook_tgkill(const struct pt_regs *regs)
{
	pid_t tid = (pid_t)regs->regs[1];
	int sig = (int)regs->regs[2];

	if ((sig == SIG_ABORT || sig == SIG_KILL) && is_target_pid(tid)) {
		pr_info("bsac_hook: blocked tgkill(_, %d, %d) targeting %s\n",
			tid, sig, TARGET_COMM);
		return 0;
	}
	return orig_tgkill(regs);
}

/* ------------------------------------------------------------------ */
/* Module init / exit                                                  */
/* ------------------------------------------------------------------ */

static int __init bsac_hook_init(void)
{
	pr_info("bsac_hook: loading\n");

	sys_call_table = (void **)kallsyms_lookup_name("sys_call_table");
	if (!sys_call_table) {
		pr_err("bsac_hook: sys_call_table not found via kallsyms\n");
		return -ENOENT;
	}
	pr_info("bsac_hook: sys_call_table @ %px\n", sys_call_table);

	/* Save originals */
	orig_exit_group = (syscall_fn_t)sys_call_table[__NR_exit_group_arm64];
	orig_kill       = (syscall_fn_t)sys_call_table[__NR_kill_arm64];
	orig_tgkill     = (syscall_fn_t)sys_call_table[__NR_tgkill_arm64];

	pr_info("bsac_hook: orig exit_group=%px kill=%px tgkill=%px\n",
		orig_exit_group, orig_kill, orig_tgkill);

	/* Make syscall table writable */
	if (make_sct_rw((unsigned long)sys_call_table) != 0) {
		pr_err("bsac_hook: failed to make sys_call_table writable\n");
		return -EPERM;
	}

	/* Install hooks */
	sys_call_table[__NR_exit_group_arm64] = (void *)hook_exit_group;
	sys_call_table[__NR_kill_arm64]       = (void *)hook_kill;
	sys_call_table[__NR_tgkill_arm64]     = (void *)hook_tgkill;

	/* Restore read-only */
	make_sct_ro((unsigned long)sys_call_table);

	pr_info("bsac_hook: hooks installed (exit_group=%px kill=%px tgkill=%px)\n",
		hook_exit_group, hook_kill, hook_tgkill);
	return 0;
}

static void __exit bsac_hook_exit(void)
{
	pr_info("bsac_hook: unloading, restoring original syscalls\n");

	if (make_sct_rw((unsigned long)sys_call_table) != 0) {
		pr_err("bsac_hook: cannot restore -- table not writable!\n");
		return;
	}

	sys_call_table[__NR_exit_group_arm64] = (void *)orig_exit_group;
	sys_call_table[__NR_kill_arm64]       = (void *)orig_kill;
	sys_call_table[__NR_tgkill_arm64]     = (void *)orig_tgkill;

	make_sct_ro((unsigned long)sys_call_table);

	pr_info("bsac_hook: original syscalls restored\n");
}

module_init(bsac_hook_init);
module_exit(bsac_hook_exit);
