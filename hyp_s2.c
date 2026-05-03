#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "hyp_s2.h"

#define L1_ENTRIES	1024
#define L2_ENTRIES	512
#define L3_ENTRIES	512

#define L1_SHIFT	30
#define L2_SHIFT	21
#define L3_SHIFT	12

static void flush_dcache_range(void *addr, size_t len)
{
	u64 line_size = 64;
	u64 start = (u64)addr & ~(line_size - 1);
	u64 end = (u64)addr + len;

	for (; start < end; start += line_size)
		asm volatile("dc civac, %0" :: "r"(start) : "memory");
	asm volatile("dsb ish" ::: "memory");
}

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

/* Find or allocate an L2 table for the given L1 index */
static int find_or_alloc_l2(struct s2_tables *t, int l1_idx)
{
	int i, j;
	u64 gb_base, pa;
	unsigned long pg;

	for (i = 0; i < t->num_l2; i++) {
		if (t->l2[i].l1_idx == l1_idx)
			return i;
	}

	if (t->num_l2 >= MAX_L2_TABLES) {
		pr_err("hypsniff: too many L2 tables (max %d)\n", MAX_L2_TABLES);
		return -ENOMEM;
	}

	pg = kfn_get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
	if (!pg)
		return -ENOMEM;

	i = t->num_l2;
	t->l2[i].va = (u64 *)pg;
	t->l2[i].pa = at_virt_to_phys(t->l2[i].va);
	t->l2[i].l1_idx = l1_idx;

	gb_base = (u64)l1_idx << L1_SHIFT;
	for (j = 0; j < L2_ENTRIES; j++) {
		pa = gb_base + ((u64)j << L2_SHIFT);
		t->l2[i].va[j] = pa | S2_BLOCK_ATTRS;
	}

	flush_dcache_range(t->l2[i].va, PAGE_SIZE);

	t->l1[l1_idx] = S2_TABLE_DESC(t->l2[i].pa);
	flush_dcache_range(&t->l1[l1_idx], sizeof(u64));

	t->num_l2++;
	pr_info("hypsniff: allocated L2[%d] for L1[%d] at PA 0x%llx\n",
		i, l1_idx, (u64)t->l2[i].pa);
	return i;
}

/* Find or allocate an L3 table for the given L1+L2 index pair */
static int find_or_alloc_l3(struct s2_tables *t, int l2_slot, int l2_idx)
{
	int i, j;
	u64 mb_base, pa;
	unsigned long pg;

	for (i = 0; i < t->num_l3; i++) {
		if (t->l3[i].l1_idx == t->l2[l2_slot].l1_idx &&
		    t->l3[i].l2_idx == l2_idx)
			return i;
	}

	if (t->num_l3 >= MAX_L3_TABLES) {
		pr_err("hypsniff: too many L3 tables (max %d)\n", MAX_L3_TABLES);
		return -ENOMEM;
	}

	pg = kfn_get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
	if (!pg)
		return -ENOMEM;

	i = t->num_l3;
	t->l3[i].va = (u64 *)pg;
	t->l3[i].pa = at_virt_to_phys(t->l3[i].va);
	t->l3[i].l1_idx = t->l2[l2_slot].l1_idx;
	t->l3[i].l2_idx = l2_idx;
	t->l3[i].target_count = 0;

	mb_base = ((u64)t->l2[l2_slot].l1_idx << L1_SHIFT) +
		  ((u64)l2_idx << L2_SHIFT);
	for (j = 0; j < L3_ENTRIES; j++) {
		pa = mb_base + ((u64)j << L3_SHIFT);
		t->l3[i].va[j] = pa | S2_PAGE_ATTRS;
	}

	flush_dcache_range(t->l3[i].va, PAGE_SIZE);

	t->l2[l2_slot].va[l2_idx] = S2_TABLE_DESC(t->l3[i].pa);
	flush_dcache_range(&t->l2[l2_slot].va[l2_idx], sizeof(u64));

	t->num_l3++;
	pr_info("hypsniff: allocated L3[%d] for L2[%d][%d] at PA 0x%llx\n",
		i, l2_slot, l2_idx, (u64)t->l3[i].pa);
	return i;
}

/* Find L3 table VA containing a given PTE PA, return pointer to the entry */
static u64 *find_pte_va(struct s2_tables *t, phys_addr_t pte_pa)
{
	int i;
	phys_addr_t table_pa;
	unsigned int offset;

	for (i = 0; i < t->num_l3; i++) {
		table_pa = t->l3[i].pa;
		if (pte_pa >= table_pa && pte_pa < table_pa + PAGE_SIZE) {
			offset = (pte_pa - table_pa) / sizeof(u64);
			return &t->l3[i].va[offset];
		}
	}
	return NULL;
}

int hyp_s2_build(struct s2_tables *t)
{
	int i;
	u64 pa;

	memset(t, 0, sizeof(*t));

	if (!kfn_get_free_pages)
		return -ENOENT;

	t->l1 = (u64 *)kfn_get_free_pages(GFP_KERNEL | __GFP_ZERO, 1);
	if (!t->l1)
		return -ENOMEM;
	t->l1_pa = at_virt_to_phys(t->l1);

	for (i = 0; i < L1_ENTRIES; i++) {
		pa = (u64)i << L1_SHIFT;
		t->l1[i] = pa | S2_BLOCK_ATTRS;
	}

	flush_dcache_range(t->l1, 2 * PAGE_SIZE);

	pr_info("hypsniff: s2 L1 built at PA 0x%llx, %d 1GB blocks\n",
		(u64)t->l1_pa, L1_ENTRIES);
	return 0;
}

int hyp_s2_drill_down_target(struct s2_tables *t, phys_addr_t target_pa,
			     phys_addr_t *out_pte_pa)
{
	int l1_idx, l2_idx, l3_idx;
	int l2_slot, l3_slot;

	l1_idx = target_pa >> L1_SHIFT;
	l2_idx = (target_pa >> L2_SHIFT) & (L2_ENTRIES - 1);
	l3_idx = (target_pa >> L3_SHIFT) & (L3_ENTRIES - 1);

	if (l1_idx >= L1_ENTRIES) {
		pr_err("hypsniff: target PA 0x%llx out of range\n",
		       (u64)target_pa);
		return -EINVAL;
	}

	l2_slot = find_or_alloc_l2(t, l1_idx);
	if (l2_slot < 0)
		return l2_slot;

	l3_slot = find_or_alloc_l3(t, l2_slot, l2_idx);
	if (l3_slot < 0)
		return l3_slot;

	t->l3[l3_slot].target_count++;

	*out_pte_pa = t->l3[l3_slot].pa + (l3_idx * sizeof(u64));

	flush_dcache_range(t->l1, 2 * PAGE_SIZE);

	pr_info("hypsniff: drilled down PA 0x%llx: L1[%d]->L2[%d]->L3[%d] PTE PA 0x%llx\n",
		(u64)target_pa, l1_idx, l2_idx, l3_idx, (u64)*out_pte_pa);
	return 0;
}

void hyp_s2_set_xn_at(struct s2_tables *t, phys_addr_t pte_pa)
{
	u64 *pte = find_pte_va(t, pte_pa);

	if (!pte)
		return;
	*pte |= S2_XN;
	flush_dcache_range(pte, sizeof(u64));
}

void hyp_s2_clear_xn_at(struct s2_tables *t, phys_addr_t pte_pa)
{
	u64 *pte = find_pte_va(t, pte_pa);

	if (!pte)
		return;
	*pte &= ~S2_XN;
	flush_dcache_range(pte, sizeof(u64));
}

void hyp_s2_set_ro_at(struct s2_tables *t, phys_addr_t pte_pa)
{
	u64 *pte = find_pte_va(t, pte_pa);

	if (!pte)
		return;
	*pte = (*pte & ~S2_AP_RW) | S2_AP_RO;
	flush_dcache_range(pte, sizeof(u64));
}

void hyp_s2_clear_ro_at(struct s2_tables *t, phys_addr_t pte_pa)
{
	u64 *pte = find_pte_va(t, pte_pa);

	if (!pte)
		return;
	*pte = (*pte & ~S2_AP_RW) | S2_AP_RW;
	flush_dcache_range(pte, sizeof(u64));
}

void hyp_s2_free(struct s2_tables *t)
{
	int i;

	for (i = 0; i < t->num_l3; i++) {
		if (t->l3[i].va) {
			kfn_free_pages((unsigned long)t->l3[i].va, 0);
			t->l3[i].va = NULL;
		}
	}
	t->num_l3 = 0;

	for (i = 0; i < t->num_l2; i++) {
		if (t->l2[i].va) {
			kfn_free_pages((unsigned long)t->l2[i].va, 0);
			t->l2[i].va = NULL;
		}
	}
	t->num_l2 = 0;

	if (t->l1) {
		kfn_free_pages((unsigned long)t->l1, 1);
		t->l1 = NULL;
	}
}
