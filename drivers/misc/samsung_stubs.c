// Stubs for undefined Samsung symbols when building with system-gcc
#include <linux/types.h>

void dhd_smmu_fault_handler(void) {}
void sdfat_debug_warn_on(int a) { (void)a; }
void sec_debug_tsp_command_history(void *a, void *b) { (void)a; (void)b; }
