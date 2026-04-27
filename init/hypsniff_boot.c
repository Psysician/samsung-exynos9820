/*
 * hypsniff_boot.c — Boot-time EL2 vector install for Exynos 9820
 *
 * Called from start_kernel() after mm_init(). Uses Samsung Exynos
 * SMC 0xC2000400 to execute a small blob at EL2 that sets VBAR_EL2
 * to a page we control. The firmware snapshots this value and restores
 * it on all CPUs (idle, hotplug, big.LITTLE migration), so the vectors
 * persist forever.
 *
 * The vector page initially contains stub handlers (just eret).
 * The hypsniff.ko module later overwrites the page contents at the
 * same physical address with full capture/patching vectors.
 *
 * Exports hypsniff_el2_vectors_pa via /proc/hypsniff_vectors so the
 * module can find the physical address.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/io.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/cacheflush.h>

/* SMC wrapper from _vmm_smc.S */
extern long _vmm_goto_EL2(unsigned long magic, unsigned long entry,
			   unsigned long stack_offset, unsigned long mode,
			   unsigned long param, unsigned long size);

/* EL2 init blob boundaries from hypsniff_el2_blob.S */
extern char hypsniff_el2_blob[];
extern char hypsniff_el2_blob_end[];

/* Physical address of the persistent EL2 vector page */
unsigned long hypsniff_el2_vectors_pa;

/* Virtual address of the vector page (for module to ioremap from PA) */
static void *vector_page_va;

/* Physical address of the EL2 blob copy */
static phys_addr_t blob_page_pa;

/*
 * Minimal stub vectors — 16 entries, each just eret.
 * ARM64 exception vector table: 16 entries x 128 bytes = 2048 bytes.
 * Each entry is 32 instructions (128 bytes) max; we only use 1 (eret).
 */
static void write_stub_vectors(void *page)
{
	u32 *code = (u32 *)page;
	int i;

	/* eret = 0xD69F03E0 */
	for (i = 0; i < 16; i++) {
		/* Each vector entry is at offset i * 0x80 (128 bytes) */
		int off = i * (0x80 / sizeof(u32));
		code[off] = 0xD69F03E0; /* eret */
	}
}

/*
 * /proc/hypsniff_vectors — exports the vector page PA for the module.
 * Format: "pa=0x<hex>\n"
 */
static int vectors_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "pa=0x%lx\n", hypsniff_el2_vectors_pa);
	return 0;
}

static int vectors_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, vectors_proc_show, NULL);
}

static const struct file_operations vectors_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = vectors_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

void __init hypsniff_el2_boot_init(void)
{
	void *blob_page_va;
	size_t blob_size;
	long smc_ret;

	pr_info("hypsniff_boot: initializing EL2 vectors via SMC 0xC2000400\n");

	/*
	 * Step 1: Allocate the persistent vector page.
	 * This page will hold EL2 exception vectors forever.
	 * Must be page-aligned (4KB satisfies the 2KB VBAR requirement).
	 */
	vector_page_va = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!vector_page_va) {
		pr_err("hypsniff_boot: failed to allocate vector page\n");
		return;
	}

	hypsniff_el2_vectors_pa = virt_to_phys(vector_page_va);
	pr_info("hypsniff_boot: vector page VA=%px PA=0x%lx\n",
		vector_page_va, hypsniff_el2_vectors_pa);

	/* Write stub eret vectors — module will overwrite later */
	write_stub_vectors(vector_page_va);
	__flush_dcache_area(vector_page_va, PAGE_SIZE);

	/*
	 * Step 2: Copy the EL2 init blob to a separate page.
	 * The blob must be at a known physical address for the SMC call.
	 * It runs at EL2, so it needs to be in physical memory the
	 * firmware can access.
	 */
	blob_size = hypsniff_el2_blob_end - hypsniff_el2_blob;
	if (blob_size > PAGE_SIZE) {
		pr_err("hypsniff_boot: EL2 blob too large: %zu bytes\n",
		       blob_size);
		goto fail_blob;
	}

	blob_page_va = (void *)__get_free_page(GFP_KERNEL | __GFP_ZERO);
	if (!blob_page_va) {
		pr_err("hypsniff_boot: failed to allocate blob page\n");
		goto fail_blob;
	}

	memcpy(blob_page_va, hypsniff_el2_blob, blob_size);
	__flush_dcache_area(blob_page_va, PAGE_SIZE);

	blob_page_pa = virt_to_phys(blob_page_va);
	pr_info("hypsniff_boot: EL2 blob: %zu bytes at PA=0x%llx\n",
		blob_size, (u64)blob_page_pa);

	/*
	 * Step 3: Call SMC 0xC2000400 to execute the blob at EL2.
	 *
	 * The Exynos firmware:
	 *   1. Switches to EL2
	 *   2. Jumps to the blob at blob_page_pa
	 *   3. The blob sets VBAR_EL2 = hypsniff_el2_vectors_pa
	 *   4. The blob returns via SMC 0xC2000401 (success)
	 *   5. Firmware snapshots VBAR_EL2 and returns to EL1
	 *
	 * Arguments:
	 *   x0 = 0xC2000400 (SMC magic)
	 *   x1 = blob physical address
	 *   x2 = 4096 (stack offset)
	 *   x3 = 1 (mode)
	 *   x4 = vector page PA (passed to blob as x0)
	 *   x5 = 0 (size, unused)
	 */
	smc_ret = _vmm_goto_EL2(0xC2000400,
				blob_page_pa,
				PAGE_SIZE,
				1,
				hypsniff_el2_vectors_pa,
				0);

	if (smc_ret != 0) {
		pr_err("hypsniff_boot: SMC 0xC2000400 failed: ret=%ld\n",
		       smc_ret);
		pr_err("hypsniff_boot: EL2 vectors NOT installed\n");
		free_page((unsigned long)blob_page_va);
		goto fail_blob;
	}

	pr_info("hypsniff_boot: SMC returned 0 — VBAR_EL2 set to 0x%lx\n",
		hypsniff_el2_vectors_pa);
	pr_info("hypsniff_boot: EL2 vectors installed successfully\n");

	/* Blob page can be freed — it only ran once */
	free_page((unsigned long)blob_page_va);

	/*
	 * Step 4: Create /proc/hypsniff_vectors for the module.
	 * The module reads this to find the vector page PA, then
	 * maps it and overwrites the stub vectors with full handlers.
	 */
	if (!proc_create("hypsniff_vectors", 0444, NULL, &vectors_proc_fops))
		pr_warn("hypsniff_boot: failed to create /proc/hypsniff_vectors\n");

	return;

fail_blob:
	/*
	 * Don't free the vector page on failure — it's harmless
	 * (just contains eret stubs) and freeing init memory that
	 * might be referenced is worse than leaking 4KB.
	 */
	hypsniff_el2_vectors_pa = 0;
	pr_err("hypsniff_boot: EL2 init FAILED — module will not work\n");
}
