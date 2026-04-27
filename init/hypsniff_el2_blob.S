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
	 * Save it before we clobber registers.
	 */
	mov	x2, x0

	/*
	 * Set VBAR_EL2 to our vector page PA.
	 * VBAR_EL2 requires bits [10:0] = 0 (2KB alignment).
	 * The caller guarantees page-alignment (4KB > 2KB).
	 */
	msr	vbar_el2, x2
	isb

	/*
	 * Return to EL3 firmware via SMC.
	 * x0 = 0xC2000401 (return-from-EL2 magic)
	 * x1 = 0 (success; non-zero causes firmware to reset EL2 state)
	 */
	mov	x0, #0x0401
	movk	x0, #0xC200, lsl #16
	mov	x1, xzr
	smc	#0

	/* Should never reach here — firmware does not return after the SMC */
	b	.
ENTRY(hypsniff_el2_blob_end)

	.popsection
