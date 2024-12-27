import struct
from dataclasses import dataclass

from DyldExtractor.extraction_context import ExtractionContext
from DyldExtractor.macho.macho_context import MachOContext

from DyldExtractor.macho.macho_structs import (
	LoadCommands,
)

from DyldExtractor.macho.fixup_chains_structs import (
	dyld_chained_fixups_header,
	dyld_chained_starts_in_image,
	dyld_chained_starts_in_segment,
	ChainedPtrStart,
	ChainedFixupPointerOnDisk,
	PointerFormat,
)

class _PointerFixer(object):
	def __init__(self, extractionCtx: ExtractionContext) -> None:
		super().__init__()

		self.extractionCtx = extractionCtx
		self.machoCtx = extractionCtx.machoCtx
		self.dyldCtx = extractionCtx.dyldCtx
		self.statusBar = extractionCtx.statusBar
		self.logger = extractionCtx.logger
		self.context = extractionCtx.dyldCtx._machoCtx

	def fixChainedPointers(self) -> None:
		self.statusBar.update(unit="Chained Pointers")

		fixupsCmd = self.context.getLoadCommand((LoadCommands.LC_DYLD_CHAINED_FIXUPS,))
		chainsHeader = dyld_chained_fixups_header(self.context.file, fixupsCmd.dataoff)
		if not fixupsCmd:
			self.logger.warning("No LC_DYLD_CHAINED_FIXUPS found in mach-o.")
			return
		
		if chainsHeader.fixups_version != 0:
			self.logger.error("Unrecognised dyld_chained_fixups version.")
			return
		
		startsOffset = chainsHeader._fileOff_ + chainsHeader.starts_offset
		startsInfo = dyld_chained_starts_in_image(self.context.file, startsOffset)
		
		seg_info_offsets = self.context.readFormat("<" + "I" * startsInfo.seg_count, startsOffset + 4)
		for segInfoOffset in seg_info_offsets:
			if segInfoOffset == 0:
				continue
			segInfo = dyld_chained_starts_in_segment(self.context.file, startsOffset + segInfoOffset)
			self.fixChainedPointersInSegment(segInfo)

	def fixChainedPointersInSegment(self, segInfo: dyld_chained_starts_in_segment) -> None:
		page_start_off = 22
		for pageIndex in range(segInfo.page_count):
			offsetInPage = self.context.readFormat("<H", segInfo._fileOff_ + page_start_off + pageIndex * 2)[0]
			if offsetInPage == ChainedPtrStart.DYLD_CHAINED_PTR_START_NONE:
				continue
			
			if offsetInPage & ChainedPtrStart.DYLD_CHAINED_PTR_START_MULTI or offsetInPage & ChainedPtrStart.DYLD_CHAINED_PTR_START_LAST:
				self.logger.error("DYLD_CHAINED_PTR_START_MULTI and DYLD_CHAINED_PTR_START_LAST fixups are not supported.")
				return

			pageContentStart = self.context.header._fileOff_ + segInfo.segment_offset + (pageIndex * segInfo.page_size)
			chainOff = pageContentStart + offsetInPage
			self.walkChain(chainOff, segInfo)

	def walkChain(self, chainOff: int, segInfo: dyld_chained_starts_in_segment) -> None:
		pointer_format = segInfo.pointer_format
		if pointer_format != PointerFormat.DYLD_CHAINED_PTR_64_KERNEL_CACHE:
			self.logger.error(f"Unsupported chain pointer_format: {pointer_format}")
			return
		
		stride = 4
		chainEnd = False

		while not chainEnd:
			chain = ChainedFixupPointerOnDisk(self.context.file, chainOff)
			self.fixPointer(chain, segInfo)

			if chain._next == 0:
				chainEnd = True
			else:
				chainOff += chain._next * stride

	def fixPointer(self, chain: ChainedFixupPointerOnDisk, segInfo: dyld_chained_starts_in_segment) -> None:
		self.statusBar.update(status="Fixing Pointers")
		fixedPointer = self.context.segments[b"__TEXT"].seg.vmaddr + chain.target
		self.machoCtx.writeBytes(chain._fileOff_, struct.pack("<Q", fixedPointer))

def fixChainedPointers(extractionCtx: ExtractionContext) -> None:
	fixer = _PointerFixer(extractionCtx)
	fixer.fixChainedPointers()
