/*
 * hypsniff_el2_blob.S — Position-independent EL2 init blob
 *
 * This code executes at EL2 when called via Samsung Exynos SMC 0xC2000400.
 * It runs at an unknown physical address, so it must be fully PIC.
 *
 * Entry state (set by firmware after SMC):
 *   Running at EL2
 *   x0 = param (physical address of our persistent vector page)
 *   x1 = size (unused, 0)
 *
 * What it does:
 *   1. Sets VBAR_EL2 to the physical address in x0 (our vector page)
 *   2. Returns to EL3 via SMC with x0=0xC2000401, x1=0 (success)
 *
 * The firmware snapshots VBAR_EL2 after this returns. Since the firmware
 * restores VBAR_EL2 from the snapshot on CPU idle/hotplug/migration,
 * our value persists forever on ALL CPUs.
 *
 * The vector page initially contains stub eret handlers. The hypsniff.ko
 * module later overwrites the page contents with full capture vectors
 * (same PA, new code). No VBAR_EL2 change needed after boot.
 */

#include <linux/linkage.h>

	.pushsection .init.rodata, "a"
	.align 4

ENTRY(hypsniff_el2_blob)
	/*
	 * x0 = physical address of vector page (2KB-aligned)
	 * x1 = physical address of stack top (page PA + PAGE_SIZE)
	 *
	 * Following the exynos-kvm-patch pattern: set ALL EL2 state
	 * needed for HVC to work, because the firmware snapshots
	 * everything at SMC return and restores it on CPU events.
	 */

	/* 1. Set VBAR_EL2 — our exception vectors */
	msr	vbar_el2, x0
	isb

	/* 2. Set SP_EL2 — handler needs a valid stack for stp/ldp */
	mov	sp, x1
	isb

	/* 3. Set HCR_EL2 — CRITICAL for HVC routing
	 *    RW (bit 31) = 1: EL1 is AArch64 (without this, kernel crashes)
	 *    HCD (bit 29) = 0: HVC enabled (EL1 can issue HVC to EL2)
	 *    All other bits = 0: no stage-2, no trapping, no VHE
	 */
	mov	x2, #(1 << 31)		/* HCR_EL2 = 0x80000000 */
	msr	hcr_el2, x2
	isb

	/* 4. Clear VTTBR_EL2 — no stage-2 until module sets it up */
	msr	vttbr_el2, xzr
	isb

	/*
	 * Return to EL3 firmware via SMC.
	 * x0 = 0xC2000401 (return-from-EL2 magic)
	 * x1 = 0 (success; non-zero causes firmware to reset EL2 state)
	 * Firmware snapshots ALL EL2 state at this point.
	 */
	mov	x0, #0x0401
	movk	x0, #0xC200, lsl #16
	mov	x1, xzr
	smc	#0

	/* Should never reach here — firmware does not return after the SMC */
	b	.
ENTRY(hypsniff_el2_blob_end)

	.popsection
