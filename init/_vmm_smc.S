/*
 * _vmm_smc.S — SMC wrapper for Exynos EL2 bootstrap
 *
 * Calls Samsung Exynos SMC 0xC2000400 to execute code at EL2 during boot.
 * The firmware runs the provided blob at EL2, then returns to EL1.
 *
 * Arguments map directly to ARM64 SMC calling convention:
 *   x0 = magic (0xC2000400)
 *   x1 = physical address of EL2 init blob
 *   x2 = stack offset / size
 *   x3 = mode
 *   x4 = param (physical address of vector page)
 *   x5 = param size
 *
 * Returns x0 from SMC (0 = success).
 */

#include <linux/linkage.h>

ENTRY(_vmm_goto_EL2)
	smc	#0
	ret
ENDPROC(_vmm_goto_EL2)
