import bisect
from typing import Dict

from DyldExtractor.extraction_context import ExtractionContext
from DyldExtractor import leb128

from DyldExtractor.macho.macho_structs import LoadCommands
from DyldExtractor.macho.macho_constants import *


class _RegularRebaseGenerator(object):

	def __init__(self, extractionCtx: ExtractionContext) -> None:
		"""Generate regular rebase info.

		Generate rebase info in the old format, where
		it was stored in the dyld_info load command.
		"""
		super().__init__()

		self._machoCtx = extractionCtx.machoCtx
		self._ptrs = extractionCtx.ptrTracker.ptrLocs
		self._logger = extractionCtx.logger
		self._statusBar = extractionCtx.statusBar

		self._rebaseInfo = bytearray()
		pass

	def run(self) -> None:
		self._initializeInfo()
		self._generate()
		self._finalizeInfo()

		# TODO: add to linkedit
		pass

	def _sortPtrs(self) -> Dict[int, int]:
		"""Sort all the pointers.

		Returns:
			A dict of segment indices and a segment offsets.
		"""

		sortedPtrs = {}
		ptrsSorted = 0

		ptrs = self._ptrs.sort()
		for segI, seg in enumerate(self._machoCtx.segmentsI):
			seg = seg.seg
			lowBound = bisect.bisect_left(ptrs, seg.vmaddr)
			highBound = bisect.bisect_right(
				ptrs,
				seg.vmaddr + seg.vmsize,
				lo=lowBound
			)

			ptrGroup = ptrs[lowBound:highBound]
			sortedPtrs[segI] = ptrGroup
			ptrsSorted += len(ptrGroup)
			pass

		if ptrsSorted != len(self._ptrs):
			self._logger.error("Missed some pointers while sorting!")
			pass

		return sortedPtrs

	def _generate(self) -> None:
		ptrs = self._sortPtrs()

		for segI, offsets in ptrs.items():
			self._statusBar.update(status="Generating")

			for offset in offsets:
				self._rebaseInfo.append(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | segI)
				self._rebaseInfo.extend(leb128.encodeUleb128(offset))
				self._rebaseInfo.append(REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1)
				pass
			pass
		pass

	def _initializeInfo(self) -> None:
		self._rebaseInfo.append(
			REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER
		)
		pass

	def _finalizeInfo(self) -> None:
		self._rebaseInfo.append(REBASE_OPCODE_DONE)
		pass
	pass


def generateRebaseInfo(extractionCtx: ExtractionContext) -> None:
	extractionCtx.statusBar.update(unit="Rebase Generator")

	dyldInfo = extractionCtx.machoCtx.getLoadCommand(
		(LoadCommands.LC_DYLD_INFO, LoadCommands.LC_DYLD_INFO_ONLY)
	)
	if dyldInfo:
		_RegularRebaseGenerator(extractionCtx).run()
		pass
	pass
