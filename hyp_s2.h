#ifndef _HYP_S2_H
#define _HYP_S2_H

#ifdef __ASSEMBLY__

#define HYPSNIFF_HVC_INIT	4
#define HYPSNIFF_HVC_TLBI	5
#define HYPSNIFF_HVC_FINI	6
#define HYPSNIFF_HVC_SET_SHARED	7

#define HVC_SET_VECTORS		0
#define HVC_SOFT_RESTART	1
#define HVC_RESET_VECTORS	2
#define HVC_STUB_HCALL_NR	3

/* v2 shared_data offsets (assembly) */
#define SHARED_OFF_ORIG_VECTORS	16
#define SHARED_OFF_CAP_BUF	24
#define SHARED_OFF_CAP_IDX	32
#define SHARED_OFF_CAP_COUNT	36
#define SHARED_OFF_CAP_MAX	40
#define SHARED_OFF_NUM_TARGETS	44
#define SHARED_OFF_TARGETS_BASE	48
#define SHARED_OFF_SYNC_COUNT	56
#define SHARED_OFF_PERM_COUNT	60

/* Target descriptor offsets (64 bytes each) */
#define TGT_OFF_IPA		0
#define TGT_OFF_PTE_PA		8
#define TGT_OFF_TYPE		16
#define TGT_OFF_ARMED		20
#define TGT_OFF_ACTION		24
#define TGT_OFF_PATCH_MASK	28
#define TGT_OFF_PATCH_X0	32
#define TGT_OFF_PATCH_PC	40
#define TGT_SIZE_SHIFT		6	/* 64 bytes = 1 << 6 */

/* Capture entry offsets (128 bytes each) */
#define CAP_OFF_PC		64
#define CAP_OFF_SP		72
#define CAP_OFF_TIMESTAMP	80
#define CAP_OFF_PID		88
#define CAP_OFF_TARGET_ID	92
#define CAP_OFF_CAP_TYPE	94
#define CAP_OFF_FAR		96
#define CAP_OFF_WRITE_VAL	104
#define CAP_OFF_WRITE_SIZE	112

#define CAP_ENTRY_SIZE		128
#define CAP_ENTRY_SHIFT		7	/* 128 = 1 << 7 */
#define MAX_HYP_CAPTURES	32
#define MAX_HYP_CAPTURES_MASK	31

#define ESR_EC_SHIFT		26
#define ESR_EC_IABT_LOW		0x20
#define ESR_EC_DABT_LOW		0x24
#define ESR_EC_HVC64		0x16
#define ESR_FSC_MASK		0x3F
#define ESR_FSC_TYPE_MASK	0x3C
#define ESR_FSC_PERM		0x0C

/* ESR fields for data abort */
#define ESR_SAS_SHIFT		22
#define ESR_SAS_MASK		0x3
#define ESR_SRT_SHIFT		16
#define ESR_SRT_MASK		0x1F

/* Action types */
#define ACTION_CAPTURE		0
#define ACTION_PATCH		1
#define ACTION_SKIP		2

/* Target types */
#define TARGET_TYPE_EXEC	0
#define TARGET_TYPE_DATA	1

/* S2 PTE bits */
#define S2_XN_BIT		54
#define S2_S2AP_RO_BITS	0xC0	/* bits [7:6] = 0b11 = S2AP RW; 0xC0 sets both */

#else /* C code */

#include <linux/types.h>

#define MAX_HYP_CAPTURES	32
#define MAX_TARGETS		8
#define MAX_L2_TABLES		8
#define MAX_L3_TABLES		16

#define HYPSNIFF_HVC_INIT	4
#define HYPSNIFF_HVC_TLBI	5
#define HYPSNIFF_HVC_FINI	6
#define HYPSNIFF_HVC_SET_SHARED	7

/* Target types */
#define TARGET_TYPE_EXEC	0
#define TARGET_TYPE_DATA	1

/* Action types */
#define ACTION_CAPTURE		0
#define ACTION_PATCH		1
#define ACTION_SKIP		2

/* Legacy aliases used by hypsniff_main.c */
#define PATCH_ACTION_CAPTURE	ACTION_CAPTURE
#define PATCH_ACTION_PATCH	ACTION_PATCH
#define PATCH_ACTION_SKIP	ACTION_SKIP

/* Stage-2 descriptor bits */
#define S2_DESC_VALID		(1UL << 0)
#define S2_DESC_TABLE		(3UL << 0)
#define S2_DESC_BLOCK		(1UL << 0)
#define S2_DESC_PAGE		(3UL << 0)
#define S2_AF			(1UL << 10)
#define S2_SH_INNER		(3UL << 8)
#define S2_AP_RW		(3UL << 6)
#define S2_AP_RO		(1UL << 6)
#define S2_MEMATTR_NORMAL	(0xFUL << 2)
#define S2_XN			(1UL << 54)

#define S2_BLOCK_ATTRS		(S2_AF | S2_SH_INNER | S2_AP_RW | \
				 S2_MEMATTR_NORMAL | S2_DESC_BLOCK)
#define S2_PAGE_ATTRS		(S2_AF | S2_SH_INNER | S2_AP_RW | \
				 S2_MEMATTR_NORMAL | S2_DESC_PAGE)
#define S2_TABLE_DESC(pa)	(((u64)(pa) & ~0xFFFUL) | S2_DESC_TABLE)

struct hyp_target_desc {
	u64 ipa;
	u64 pte_pa;
	u32 type;		/* 0=exec, 1=data */
	u32 armed;
	u32 action;		/* 0=capture, 1=patch, 2=skip */
	u32 patch_mask;		/* bit0=x0, bit8=PC */
	u64 patch_x0;
	u64 patch_pc;
};

struct hyp_capture_entry {
	u64 regs[8];		/* x0-x7 */
	u64 pc;			/* ELR_EL2 */
	u64 sp;			/* SP_EL1 */
	u64 timestamp;		/* CNTPCT_EL0 */
	u32 pid;
	u16 target_id;
	u16 cap_type;		/* 0=exec, 1=data */
	u64 far;		/* FAR_EL2 (data watchpoint) */
	u64 write_val;
	u32 write_size;
	u32 _pad[3];		/* pad to 128 bytes */
};

struct hyp_shared_data {
	u64 reserved0;		/* +0x00 */
	u64 reserved1;		/* +0x08 */
	u64 orig_vectors_pa;	/* +0x10 */
	u64 cap_buf_pa;		/* +0x18 */
	volatile u32 cap_idx;	/* +0x20 */
	volatile u32 cap_count;	/* +0x24 */
	u32 cap_max;		/* +0x28 */
	u32 num_targets;	/* +0x2C */
	u64 targets_base_pa;	/* +0x30 */
	u32 dbg_sync_count;	/* +0x38 */
	u32 dbg_perm_count;	/* +0x3C */

	u64 vtcr_val;
	u64 vttbr_val;
	u64 _reserved[4];

	struct hyp_capture_entry entries[MAX_HYP_CAPTURES];
};

struct s2_l2_table {
	u64 *va;
	phys_addr_t pa;
	int l1_idx;
};

struct s2_l3_table {
	u64 *va;
	phys_addr_t pa;
	int l1_idx;
	int l2_idx;
	int target_count;
};

struct s2_tables {
	u64 *l1;
	phys_addr_t l1_pa;
	struct s2_l2_table l2[MAX_L2_TABLES];
	int num_l2;
	struct s2_l3_table l3[MAX_L3_TABLES];
	int num_l3;
};

/* Runtime-resolved function pointers (set by hypsniff_main.c init) */
typedef unsigned long (*get_free_pages_fn)(unsigned int gfp, unsigned int order);
typedef void (*free_pages_fn)(unsigned long addr, unsigned int order);

extern get_free_pages_fn kfn_get_free_pages;
extern free_pages_fn kfn_free_pages;

int hyp_s2_build(struct s2_tables *t);
int hyp_s2_drill_down_target(struct s2_tables *t, phys_addr_t target_pa,
			     phys_addr_t *out_pte_pa);
void hyp_s2_set_xn_at(struct s2_tables *t, phys_addr_t pte_pa);
void hyp_s2_clear_xn_at(struct s2_tables *t, phys_addr_t pte_pa);
void hyp_s2_set_ro_at(struct s2_tables *t, phys_addr_t pte_pa);
void hyp_s2_clear_ro_at(struct s2_tables *t, phys_addr_t pte_pa);
void hyp_s2_free(struct s2_tables *t);

#endif /* __ASSEMBLY__ */
#endif /* _HYP_S2_H */
