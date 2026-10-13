/* probe93/iommu.elf — read the 8 AMD-Vi IOMMU MMIO windows' DTRB/CBRB/CTRL/status.
 * DTRB[51:12] = device-table host-PA, CBRB[51:12] = command-buffer host-PA — both land
 * inside the HV carve-out (0x60000000..0x70000000), pinning the HV host-PA region on ANY
 * boot (deterministic, no NPT coin-flip). MMIO windows are device-mapped + readable.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ps5/kernel.h>
#include <ps5/payload.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

int main(void) {
  /* MMIO base PA = 0x1130000 (IOMMU_MMIO_PA.md); VA = PHYS_TO_DMAP = DMAP_BASE + PA.
   * DMAP base is randomized per boot, so use the live symbol, not a hardcoded VA. */
  uint64_t dmap = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  const uint64_t base = dmap + 0x1130000ull;
  char b[256];
  snprintf(b, sizeof b, "iommu: fw=0x%x kdata=0x%llx",
           kernel_get_fw_version(),
           (unsigned long long)payload_get_args()->kdata_base_addr);
  printf("%s\n", b);
  for (int n = 0; n < 8; n++) {
    uint64_t va = base + (uint64_t)n * 0x4000;
    uint64_t dtrb=0, cbrb=0, ctrl=0, tail=0, status=0;
    int r0 = kernel_copyout((intptr_t)(va+0x00),   &dtrb,   8);
    int r1 = kernel_copyout((intptr_t)(va+0x08),   &cbrb,   8);
    int r2 = kernel_copyout((intptr_t)(va+0x18),   &ctrl,   8);
    int r3 = kernel_copyout((intptr_t)(va+0x2008), &tail,   8);
    int r4 = kernel_copyout((intptr_t)(va+0x2020), &status, 8);
    uint64_t dt_pa  = (dtrb >> 12) & 0xFFFFFFFFFFull;
    uint64_t cb_pa  = (cbrb >> 12) & 0xFFFFFFFFFFull;
    snprintf(b, sizeof b,
      "win%d r=%d,%d,%d,%d,%d DTRB=0x%llx(dt_pa=0x%llx) CBRB=0x%llx(cb_pa=0x%llx) CTRL=0x%llx tail=0x%llx status=0x%llx",
      n, r0, r1, r2, r3, r4,
      (unsigned long long)dtrb, (unsigned long long)dt_pa,
      (unsigned long long)cbrb, (unsigned long long)cb_pa,
      (unsigned long long)ctrl, (unsigned long long)tail, (unsigned long long)status);
    printf("%s\n", b);
  }
  return 0;
}
