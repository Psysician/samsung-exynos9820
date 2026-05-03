#include <linux/linkage.h>
#include "hyp_s2.h"

.macro ventry label
	.align 7
	b	\label
.endm

	.pushsection .text, "ax"
	.align 11

ENTRY(hypsniff_vectors)
	/* EL2t */
	ventry hyp_passthrough		/* +0x000 Sync EL2t */
	ventry hyp_passthrough		/* +0x080 IRQ EL2t */
	ventry hyp_passthrough		/* +0x100 FIQ EL2t */
	ventry hyp_passthrough		/* +0x180 Error EL2t */

	/* EL2h */
	ventry hyp_passthrough		/* +0x200 Sync EL2h */
	ventry hyp_passthrough		/* +0x280 IRQ EL2h */
	ventry hyp_passthrough		/* +0x300 FIQ EL2h */
	ventry hyp_passthrough		/* +0x380 Error EL2h */

	/* 64-bit EL1 */
	ventry el1_sync_handler		/* +0x400 Sync 64-bit EL1 */
	ventry hyp_passthrough		/* +0x480 IRQ 64-bit EL1 */
	ventry hyp_passthrough		/* +0x500 FIQ 64-bit EL1 */
	ventry hyp_passthrough		/* +0x580 Error 64-bit EL1 */

	/* 32-bit EL1 */
	ventry hyp_passthrough		/* +0x600 Sync 32-bit EL1 */
	ventry hyp_passthrough		/* +0x680 IRQ 32-bit EL1 */
	ventry hyp_passthrough		/* +0x700 FIQ 32-bit EL1 */
	ventry hyp_passthrough		/* +0x780 Error 32-bit EL1 */
END(hypsniff_vectors)

	/*
	 * Shared data PA slot at vectors + 0x800.
	 * The vector table is 16 entries * 128 bytes = 2048 (0x800).
	 * This .space ensures correct placement after the last entry slot.
	 */
	.space (0x800 - (. - hypsniff_vectors))
ENTRY(hypsniff_shared_pa_slot)
	.quad 0
END(hypsniff_shared_pa_slot)

ENTRY(hypsniff_vectors_end)
END(hypsniff_vectors_end)

hyp_passthrough:
	eret

el1_sync_handler:
	/* Fix SP_EL2 before any stack use. Samsung EL3 may leave it invalid. */
	msr	tpidr_el2, x0
	movz	x0, #0x0000
	movk	x0, #0x8705, lsl #16
	mov	sp, x0
	mrs	x0, tpidr_el2

	stp	x0, x1, [sp, #-16]!
	stp	x2, x3, [sp, #-16]!

	mrs	x0, esr_el2
	lsr	x1, x0, #ESR_EC_SHIFT

	/* Increment sync_count in shared_data */
	mrs	x2, vbar_el2
	ldr	x2, [x2, #0x800]
	cbz	x2, 1f
	ldr	w3, [x2, #SHARED_OFF_SYNC_COUNT]
	add	w3, w3, #1
	str	w3, [x2, #SHARED_OFF_SYNC_COUNT]
1:

	/* Check for HVC64 (EC = 0x16) */
	cmp	x1, #ESR_EC_HVC64
	b.eq	handle_hvc

	/* Check FSC for permission fault (bits [5:2] == 0x0C) */
	and	x2, x0, #ESR_FSC_TYPE_MASK
	cmp	x2, #ESR_FSC_PERM
	b.ne	passthrough_restore

	/* Increment perm_count in shared_data */
	mrs	x2, vbar_el2
	ldr	x2, [x2, #0x800]
	cbz	x2, 2f
	ldr	w3, [x2, #SHARED_OFF_PERM_COUNT]
	add	w3, w3, #1
	str	w3, [x2, #SHARED_OFF_PERM_COUNT]
2:

	/* Dispatch by EC: IABT (0x20) or DABT (0x24) */
	cmp	x1, #ESR_EC_IABT_LOW
	b.eq	handle_exec_fault
	cmp	x1, #ESR_EC_DABT_LOW
	b.eq	handle_data_fault
	b	passthrough_restore

passthrough_restore:
	ldp	x2, x3, [sp], #16
	ldp	x0, x1, [sp], #16
	eret

/*
 * HVC dispatcher — v2 dispatches to codes 4,5,6,7 only.
 */
handle_hvc:
	ldr	x0, [sp, #16]		/* original x0 = HVC code */

	cmp	x0, #HYPSNIFF_HVC_INIT
	b.eq	hvc_init
	cmp	x0, #HYPSNIFF_HVC_TLBI
	b.eq	hvc_tlbi
	cmp	x0, #HYPSNIFF_HVC_FINI
	b.eq	hvc_fini
	cmp	x0, #HYPSNIFF_HVC_SET_SHARED
	b.eq	hvc_set_shared

	/* Unknown HVC */
	ldp	x2, x3, [sp], #16
	ldp	x0, x1, [sp], #16
	movz	x0, #0xca11
	movk	x0, #0xbad, lsl #16
	eret

/*
 * Dead code: hvc_set_vectors / hvc_reset_vectors.
 * Present in binary but unreachable from dispatcher.
 */
hvc_set_vectors:
	ldr	x1, [sp, #24]
	msr	vbar_el2, x1
	ldp	x2, x3, [sp], #16
	ldp	x0, x1, [sp], #16
	mov	x0, xzr
	eret

hvc_reset_vectors:
	mrs	x1, vbar_el2
	ldr	x1, [x1, #0x800]
	cbz	x1, 1f
	ldr	x1, [x1, #SHARED_OFF_ORIG_VECTORS]
	cbz	x1, 1f
	msr	vbar_el2, x1
1:	ldp	x2, x3, [sp], #16
	ldp	x0, x1, [sp], #16
	mov	x0, xzr
	eret

hvc_init:
	ldr	x1, [sp, #24]		/* vtcr */
	ldr	x2, [sp, #0]		/* vttbr */
	ldr	x3, [sp, #8]		/* stack_pa */

	msr	vtcr_el2, x1
	isb
	msr	vttbr_el2, x2
	isb

	mov	sp, x3
	isb

	mrs	x0, hcr_el2
	orr	x0, x0, #1
	msr	hcr_el2, x0
	isb

	mov	x0, xzr
	eret

hvc_tlbi:
	ldr	x1, [sp, #24]		/* IPA */
	lsr	x1, x1, #12
	dsb	ishst
	tlbi	ipas2e1is, x1
	dsb	ish
	tlbi	vmalle1is
	dsb	ish
	isb
	ldp	x2, x3, [sp], #16
	ldp	x0, x1, [sp], #16
	mov	x0, xzr
	eret

hvc_fini:
	mrs	x0, hcr_el2
	and	x0, x0, #~1
	msr	hcr_el2, x0
	isb
	msr	vttbr_el2, xzr
	isb
	ldp	x2, x3, [sp], #16
	ldp	x0, x1, [sp], #16
	mov	x0, xzr
	eret

/*
 * HVC(7) SET_SHARED: write shared_data PA to VBAR_EL2+0x800, flush dcache.
 */
hvc_set_shared:
	ldr	x1, [sp, #24]		/* shared_data PA */
	mrs	x2, vbar_el2
	str	x1, [x2, #0x800]
	dc	civac, x2
	dsb	ish
	ldp	x2, x3, [sp], #16
	ldp	x0, x1, [sp], #16
	mov	x0, xzr
	eret

/*
 * Stage-2 IABT permission fault handler — multi-target exec scan.
 * At entry: x0=ESR, x1=EC, x2/x3 on stack.
 */
handle_exec_fault:
	stp	x4, x5, [sp, #-16]!
	stp	x6, x7, [sp, #-16]!

	/* Compute faulting IPA from HPFAR */
	mrs	x2, hpfar_el2
	and	x2, x2, #~0xF
	lsl	x2, x2, #8

	/* Load shared_data */
	mrs	x3, vbar_el2
	ldr	x3, [x3, #0x800]
	cbz	x3, exec_nomatch

	/* Load target count and targets base */
	ldr	w4, [x3, #SHARED_OFF_NUM_TARGETS]
	ldr	x5, [x3, #SHARED_OFF_TARGETS_BASE]
	cbz	w4, exec_nomatch

	mov	w6, #0			/* loop index */

exec_scan:
	lsl	x7, x6, #TGT_SIZE_SHIFT
	add	x7, x5, x7		/* x7 = target descriptor */

	ldr	w0, [x7, #TGT_OFF_ARMED]
	cbz	w0, exec_next

	ldr	w0, [x7, #TGT_OFF_TYPE]
	cbnz	w0, exec_next		/* skip non-exec targets */

	ldr	x0, [x7, #TGT_OFF_IPA]
	cmp	x0, x2
	b.eq	exec_hit

exec_next:
	add	w6, w6, #1
	cmp	w6, w4
	b.lt	exec_scan

exec_nomatch:
	ldp	x6, x7, [sp], #16
	ldp	x4, x5, [sp], #16
	ldp	x2, x3, [sp], #16
	ldp	x0, x1, [sp], #16
	eret

/*
 * Exec target hit — capture registers.
 * Stack: [x6,x7] [x4,x5] [x2,x3] [x0,x1]
 *        sp+0    sp+16   sp+32   sp+48
 */
exec_hit:
	/* Compute capture entry address */
	ldr	x0, [x3, #SHARED_OFF_CAP_BUF]
	ldr	w1, [x3, #SHARED_OFF_CAP_IDX]
	and	w2, w1, #MAX_HYP_CAPTURES_MASK
	lsl	x2, x2, #CAP_ENTRY_SHIFT
	add	x0, x0, x2		/* x0 = capture entry */

	/* Store x4-x7 from stack (pushed after original x0-x3) */
	ldp	x4, x5, [sp, #16]	/* saved x4, x5 */
	stp	x4, x5, [x0, #32]
	ldp	x4, x5, [sp]		/* saved x6, x7 */
	stp	x4, x5, [x0, #48]

	/* Store ELR_EL2, SP_EL1 */
	mrs	x4, elr_el2
	mrs	x5, sp_el1
	stp	x4, x5, [x0, #CAP_OFF_PC]

	/* Timestamp */
	mrs	x4, cntpct_el0
	str	x4, [x0, #CAP_OFF_TIMESTAMP]

	/* PID = 0 (no access at EL2), target_id, cap_type */
	str	wzr, [x0, #CAP_OFF_PID]
	strh	w6, [x0, #CAP_OFF_TARGET_ID]
	strh	wzr, [x0, #CAP_OFF_CAP_TYPE]

	/* Clear data fields (not applicable for exec) */
	str	xzr, [x0, #CAP_OFF_FAR]
	str	xzr, [x0, #CAP_OFF_WRITE_VAL]
	str	wzr, [x0, #CAP_OFF_WRITE_SIZE]

	/* Store original x0-x3 from stack */
	ldp	x4, x5, [sp, #48]	/* original x0, x1 */
	stp	x4, x5, [x0, #0]
	ldp	x4, x5, [sp, #32]	/* original x2, x3 */
	stp	x4, x5, [x0, #16]

	/* Increment cap_idx */
	add	w1, w1, #1
	str	w1, [x3, #SHARED_OFF_CAP_IDX]

	/* Increment cap_count (capped at MAX_HYP_CAPTURES) */
	ldr	w2, [x3, #SHARED_OFF_CAP_COUNT]
	cmp	w2, #MAX_HYP_CAPTURES
	b.ge	1f
	add	w2, w2, #1
	str	w2, [x3, #SHARED_OFF_CAP_COUNT]
1:

	/* Conditional patching based on action field */
	ldr	w4, [x7, #TGT_OFF_ACTION]
	cbz	w4, exec_disarm		/* action=0: capture only */
	cmp	w4, #ACTION_SKIP
	b.eq	exec_do_skip		/* action=2: skip function */

	/* action=1: patch selected registers */
	ldr	w5, [x7, #TGT_OFF_PATCH_MASK]
	tbz	w5, #0, exec_check_pc	/* bit0 = patch x0 */
	ldr	x4, [x7, #TGT_OFF_PATCH_X0]
	str	x4, [sp, #48]		/* overwrite saved x0 */

exec_check_pc:
	tbz	w5, #8, exec_disarm	/* bit8 = patch PC */
	ldr	x4, [x7, #TGT_OFF_PATCH_PC]
	msr	elr_el2, x4
	b	exec_disarm

exec_do_skip:
	ldr	x4, [x7, #TGT_OFF_PATCH_X0]
	str	x4, [sp, #48]		/* overwrite saved x0 */
	ldr	x4, [x7, #TGT_OFF_PATCH_PC]
	cbz	x4, exec_disarm
	msr	elr_el2, x4

exec_disarm:
	/* Clear XN on target PTE */
	ldr	x4, [x7, #TGT_OFF_PTE_PA]
	ldr	x5, [x4]
	mov	x6, #1
	lsl	x6, x6, #S2_XN_BIT
	bic	x5, x5, x6
	str	x5, [x4]

	/* TLB invalidate */
	ldr	x6, [x7, #TGT_OFF_IPA]
	lsr	x6, x6, #12
	dsb	ishst
	tlbi	ipas2e1is, x6
	dsb	ish
	tlbi	vmalle1is
	dsb	ish
	isb

	/* Mark target disarmed */
	str	wzr, [x7, #TGT_OFF_ARMED]

	/* Restore and return */
	ldp	x6, x7, [sp], #16
	ldp	x4, x5, [sp], #16
	ldp	x2, x3, [sp], #16
	ldp	x0, x1, [sp], #16
	eret

/*
 * Stage-2 DABT permission fault handler — multi-target data scan.
 * At entry: x0=ESR, x1=EC, x2/x3 on stack.
 */
handle_data_fault:
	stp	x4, x5, [sp, #-16]!
	stp	x6, x7, [sp, #-16]!

	/* Compute faulting IPA */
	mrs	x2, hpfar_el2
	and	x2, x2, #~0xF
	lsl	x2, x2, #8

	/* Load shared_data */
	mrs	x3, vbar_el2
	ldr	x3, [x3, #0x800]
	cbz	x3, data_nomatch

	/* Load target count and targets base */
	ldr	w4, [x3, #SHARED_OFF_NUM_TARGETS]
	ldr	x5, [x3, #SHARED_OFF_TARGETS_BASE]
	cbz	w4, data_nomatch

	mov	w6, #0

data_scan:
	lsl	x7, x6, #TGT_SIZE_SHIFT
	add	x7, x5, x7

	ldr	w0, [x7, #TGT_OFF_ARMED]
	cbz	w0, data_next

	ldr	w0, [x7, #TGT_OFF_TYPE]
	cmp	w0, #TARGET_TYPE_DATA
	b.ne	data_next

	ldr	x0, [x7, #TGT_OFF_IPA]
	cmp	x0, x2
	b.eq	data_hit

data_next:
	add	w6, w6, #1
	cmp	w6, w4
	b.lt	data_scan

data_nomatch:
	ldp	x6, x7, [sp], #16
	ldp	x4, x5, [sp], #16
	ldp	x2, x3, [sp], #16
	ldp	x0, x1, [sp], #16
	eret

/*
 * Data target hit — capture registers + write value.
 * Stack: [x6,x7] [x4,x5] [x2,x3] [x0,x1]
 *        sp+0    sp+16   sp+32   sp+48
 */
data_hit:
	/* Capture entry address */
	ldr	x0, [x3, #SHARED_OFF_CAP_BUF]
	ldr	w1, [x3, #SHARED_OFF_CAP_IDX]
	and	w2, w1, #MAX_HYP_CAPTURES_MASK
	lsl	x2, x2, #CAP_ENTRY_SHIFT
	add	x0, x0, x2

	/* Store x4-x7 from stack */
	ldp	x4, x5, [sp, #16]
	stp	x4, x5, [x0, #32]
	ldp	x4, x5, [sp]
	stp	x4, x5, [x0, #48]

	/* Store ELR_EL2, SP_EL1 */
	mrs	x4, elr_el2
	mrs	x5, sp_el1
	stp	x4, x5, [x0, #CAP_OFF_PC]

	/* Timestamp */
	mrs	x4, cntpct_el0
	str	x4, [x0, #CAP_OFF_TIMESTAMP]

	/* PID = 0, target_id, cap_type = 1 (data) */
	str	wzr, [x0, #CAP_OFF_PID]
	strh	w6, [x0, #CAP_OFF_TARGET_ID]
	mov	w4, #1
	strh	w4, [x0, #CAP_OFF_CAP_TYPE]

	/* FAR_EL2 = faulting data address */
	mrs	x4, far_el2
	str	x4, [x0, #CAP_OFF_FAR]

	/* Compute write size from ESR SAS field: size = 1 << SAS */
	mrs	x4, esr_el2
	lsr	x5, x4, #ESR_SAS_SHIFT
	and	x5, x5, #ESR_SAS_MASK
	mov	w2, #1
	lsl	w2, w2, w5
	str	w2, [x0, #CAP_OFF_WRITE_SIZE]

	/* Extract source register (SRT field) to get write value */
	lsr	x5, x4, #ESR_SRT_SHIFT
	and	x5, x5, #ESR_SRT_MASK

	/* x0-x7 are on stack; x8-x15 are live */
	cmp	x5, #8
	b.ge	data_live_reg

	/* x0-x7: load from stack using offset table */
	adr	x4, data_reg_offsets
	ldrb	w4, [x4, x5]
	ldr	x4, [sp, x4]
	str	x4, [x0, #CAP_OFF_WRITE_VAL]
	b	data_store_x0x3

data_live_reg:
	sub	x5, x5, #8
	cmp	x5, #8
	b.ge	data_reg_high

	/* Jump table for x8-x15 */
	adr	x4, data_live_jmp
	add	x4, x4, x5, lsl #3	/* each entry = 2 insns = 8 bytes */
	br	x4

data_live_jmp:
	str	x8, [x0, #CAP_OFF_WRITE_VAL]
	b	data_store_x0x3
	str	x9, [x0, #CAP_OFF_WRITE_VAL]
	b	data_store_x0x3
	str	x10, [x0, #CAP_OFF_WRITE_VAL]
	b	data_store_x0x3
	str	x11, [x0, #CAP_OFF_WRITE_VAL]
	b	data_store_x0x3
	str	x12, [x0, #CAP_OFF_WRITE_VAL]
	b	data_store_x0x3
	str	x13, [x0, #CAP_OFF_WRITE_VAL]
	b	data_store_x0x3
	str	x14, [x0, #CAP_OFF_WRITE_VAL]
	b	data_store_x0x3
	str	x15, [x0, #CAP_OFF_WRITE_VAL]
	b	data_store_x0x3

data_reg_high:
	str	xzr, [x0, #CAP_OFF_WRITE_VAL]

data_store_x0x3:
	/* Store original x0-x3 from stack */
	ldp	x4, x5, [sp, #48]
	stp	x4, x5, [x0, #0]
	ldp	x4, x5, [sp, #32]
	stp	x4, x5, [x0, #16]

	/* Increment cap_idx and cap_count */
	ldr	w1, [x3, #SHARED_OFF_CAP_IDX]
	add	w1, w1, #1
	str	w1, [x3, #SHARED_OFF_CAP_IDX]
	ldr	w2, [x3, #SHARED_OFF_CAP_COUNT]
	cmp	w2, #MAX_HYP_CAPTURES
	b.ge	1f
	add	w2, w2, #1
	str	w2, [x3, #SHARED_OFF_CAP_COUNT]
1:

	/* Set S2AP to read-only (set bits [7:6]) on target PTE */
	ldr	x4, [x7, #TGT_OFF_PTE_PA]
	ldr	x5, [x4]
	orr	x5, x5, #S2_S2AP_RO_BITS
	str	x5, [x4]

	/* TLB invalidate */
	ldr	x6, [x7, #TGT_OFF_IPA]
	lsr	x6, x6, #12
	dsb	ishst
	tlbi	ipas2e1is, x6
	dsb	ish
	tlbi	vmalle1is
	dsb	ish
	isb

	/* Mark target disarmed */
	str	wzr, [x7, #TGT_OFF_ARMED]

	/* Restore and return */
	ldp	x6, x7, [sp], #16
	ldp	x4, x5, [sp], #16
	ldp	x2, x3, [sp], #16
	ldp	x0, x1, [sp], #16
	eret

	.align 2
	.word 0			/* padding */

/*
 * Stack offset table for x0-x7 register extraction.
 * With 4 push pairs, stack layout: [x6,x7][x4,x5][x2,x3][x0,x1]
 *   x0=sp+48(0x30), x1=sp+56(0x38), x2=sp+32(0x20), x3=sp+40(0x28)
 *   x4=sp+16(0x10), x5=sp+24(0x18), x6=sp+0(0x00),  x7=sp+8(0x08)
 */
data_reg_offsets:
	.byte 0x30, 0x38, 0x20, 0x28, 0x10, 0x18, 0x00, 0x08

	.popsection
