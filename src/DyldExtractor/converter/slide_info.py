import struct
from dataclasses import dataclass
from typing import (
	Type,
	TypeVar,
	Union,
	Tuple,
	List
)

from DyldExtractor.extraction_context import ExtractionContext
from DyldExtractor.file_context import FileContext
from DyldExtractor.structure import Structure

from DyldExtractor.dyld.dyld_context import DyldContext
from DyldExtractor.dyld.dyld_constants import *
from DyldExtractor.dyld.dyld_structs import (
	dyld_cache_mapping_and_slide_info,
	dyld_cache_mapping_info,
	dyld_cache_slide_info2,
	dyld_cache_slide_info3,
	dyld_cache_slide_pointer3
)

from DyldExtractor.macho.macho_context import MachOContext
from DyldExtractor.macho.macho_structs import (
	segment_command_64
)


_SlideInfoMap = {
	2: dyld_cache_slide_info2,
	3: dyld_cache_slide_info3
}


@dataclass
class MappingInfo(object):
	mapping: Union[dyld_cache_mapping_info, dyld_cache_mapping_and_slide_info]
	slideInfo: Union[dyld_cache_slide_info2, dyld_cache_slide_info3]
	dyldCtx: DyldContext
	"""The context that the mapping info belongs to."""
	pass


class _V2Rebaser(object):

	def __init__(
		self,
		extractionCtx: ExtractionContext,
		mappingInfo: MappingInfo
	) -> None:
		super().__init__()

		self.statusBar = extractionCtx.statusBar
		self.logger = extractionCtx.logger
		self.machoCtx = extractionCtx.machoCtx

		self.dyldCtx = mappingInfo.dyldCtx
		self.mapping = mappingInfo.mapping
		self.slideInfo = mappingInfo.slideInfo

	def run(self) -> None:
		"""Process all slide info.
		"""

		self.statusBar.update(unit="Slide Info Rebaser")

		# get pageStarts, an array of uint_16
		pageStartsOff = self.slideInfo._fileOff_ + self.slideInfo.page_starts_offset
		pageStarts = self.dyldCtx.fileCtx.getBytes(
			pageStartsOff,
			self.slideInfo.page_starts_count * 2
		)
		pageStarts = [page[0] for page in struct.iter_unpack("<H", pageStarts)]

		for segment in self.machoCtx.segmentsI:
			self._rebaseSegment(pageStarts, segment.seg)

	def _rebaseSegment(
		self,
		pageStarts: Tuple[int],
		segment: segment_command_64
	) -> None:
		"""Process all slide info for a segment"""

		# check if the segment is included in the mapping
		if not (
			segment.vmaddr >= self.mapping.address
			and segment.vmaddr < self.mapping.address + self.mapping.size
		):
			return

		machoFile = self.machoCtx.fileForAddr(segment.vmaddr)

		# get the indices of relevent pageStarts
		dataStart = self.mapping.address
		pageSize = self.slideInfo.page_size

		startAddr = segment.vmaddr - dataStart
		startIndex = int(startAddr / pageSize)

		endAddr = ((segment.vmaddr + segment.vmsize) - dataStart) + pageSize
		endIndex = int(endAddr / pageSize)
		if endIndex == len(pageStarts) + 1:
			endIndex -= 2
			pass

		for i in range(startIndex, endIndex):
			page = pageStarts[i]

			if page == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE:
				pass
			elif page & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA:
				pageAddr = (i * pageSize) + self.mapping.address
				self.logger.warning(f"Unable to handle page extras at {hex(pageAddr)}")
			elif (page & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) == 0:
				pageOff = (i * pageSize) + self.mapping.fileOffset

				# The page offset are 32bit jumps
				self._rebasePage(machoFile, pageOff, page * 4)

				self.statusBar.update(status="Rebasing Pages")
		pass

	def _rebasePage(
		self,
		machoFile: FileContext,
		pageStart: int,
		pageOffset: int
	) -> None:
		"""Process the slide info for a page.

		Args:
			pageStart: the file offset to the page.
			pageOffset: the offset from the pageStart to the first rebase location.
		"""

		deltaMask = self.slideInfo.delta_mask
		valueMask = ~deltaMask
		valueAdd = self.slideInfo.value_add

		# basically __builtin_ctzll(deltaMask) - 2;
		deltaShift = "{0:b}".format(deltaMask)
		deltaShift = len(deltaShift) - len(deltaShift.rstrip("0"))
		deltaShift = deltaShift - 2

		delta = 1
		while delta != 0:
			loc = pageStart + pageOffset

			rawValue = self.dyldCtx.fileCtx.readFormat("<Q", loc)[0]
			delta = (rawValue & deltaMask) >> deltaShift

			newValue = rawValue & valueMask
			if valueMask != 0:
				newValue += valueAdd

			machoFile.writeBytes(loc, struct.pack("<Q", newValue))
			pageOffset += delta
		pass
	pass


class _V3Rebaser(object):

	def __init__(
		self,
		extractionCtx: ExtractionContext,
		mappingInfo: MappingInfo
	) -> None:
		super().__init__()

		self.statusBar = extractionCtx.statusBar
		self.machoCtx = extractionCtx.machoCtx

		self.dyldCtx = mappingInfo.dyldCtx
		self.mapping = mappingInfo.mapping
		self.slideInfo = mappingInfo.slideInfo

	def run(self) -> None:
		self.statusBar.update(unit="Slide Info Rebaser")

		pageStartsOff = self.slideInfo._fileOff_ + len(self.slideInfo)
		pageStarts = self.dyldCtx.fileCtx.getBytes(
			pageStartsOff,
			self.slideInfo.page_starts_count * 2
		)
		pageStarts = [page[0] for page in struct.iter_unpack("<H", pageStarts)]

		for segment in self.machoCtx.segmentsI:
			self._rebaseSegment(pageStarts, segment.seg)

	def _rebaseSegment(
		self,
		pageStarts: Tuple[int],
		segment: segment_command_64
	) -> None:
		# check if the segment is included in the mapping
		if not (
			segment.vmaddr >= self.mapping.address
			and segment.vmaddr < self.mapping.address + self.mapping.size
		):
			return

		machoFile = self.machoCtx.fileForAddr(segment.vmaddr)

		# get the indices of relevent pageStarts
		dataStart = self.mapping.address
		pageSize = self.slideInfo.page_size

		startAddr = segment.vmaddr - dataStart
		startIndex = int(startAddr / pageSize)

		endAddr = ((segment.vmaddr + segment.vmsize) - dataStart) + pageSize
		endIndex = int(endAddr / pageSize)
		endIndex = min(endIndex, len(pageStarts))

		for i in range(startIndex, endIndex):
			page = pageStarts[i]

			if page == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE:
				continue
			else:
				pageOff = (i * pageSize) + self.mapping.fileOffset
				self._rebasePage(machoFile, pageOff, page)

				self.statusBar.update(status="Rebasing Pages")
		pass

	def _rebasePage(
		self,
		machoFile: FileContext,
		pageOffset: int,
		delta: int
	) -> None:
		locOff = pageOffset

		while True:
			locOff += delta
			locInfo = dyld_cache_slide_pointer3(self.dyldCtx.fileCtx.file, locOff)

			# It appears the delta encoded in the pointers are 64bit jumps...
			delta = locInfo.plain.offsetToNextPointer * 8

			if locInfo.auth.authenticated:
				newValue = locInfo.auth.offsetFromSharedCacheBase
				newValue += self.slideInfo.auth_value_add
			else:
				value51 = locInfo.plain.pointerValue
				top8Bits = value51 & 0x0007F80000000000
				bottom43Bits = value51 & 0x000007FFFFFFFFFF
				newValue = (top8Bits << 13) | bottom43Bits

			machoFile.writeBytes(locOff, struct.pack("<Q", newValue))

			if delta == 0:
				break


def _getMappingInfo(
	extractionCtx: ExtractionContext
) -> List[MappingInfo]:
	"""Get pairs of mapping and slide info.
	"""
	dyldCtx = extractionCtx.dyldCtx
	logger = extractionCtx.logger

	mappingInfo = []

	if dyldCtx.header.slideInfoOffsetUnused:
		# Assume the legacy case with no sub caches, and only one slide info
		if dyldCtx.hasSubCaches():
			logger.error("Legacy slide info with sub caches.")
			pass

		# the version is encoded as the first uint32 field
		slideInfoOff = dyldCtx.header.slideInfoOffsetUnused
		slideInfoVer = dyldCtx.fileCtx.readFormat(slideInfoOff, "<I")[0]

		if slideInfoVer not in _SlideInfoMap:
			logger.error("Unknown slide info version: " + slideInfoVer)
			return None

		# Assume that only the second mapping has slide info
		mapping = dyldCtx.mappings[1][0]
		slideInfo = _SlideInfoMap[slideInfoVer](dyldCtx.fileCtx.file, slideInfoOff)
		mappingInfo.append(MappingInfo(mapping, slideInfo, dyldCtx))
		pass

	else:
		for mapping, context in dyldCtx.mappings:
			if not context.headerContainsField("mappingWithSlideOffset"):
				logger.error("Unable to pair mapping with slide info.")
				continue

			# Get the expanded mapping info
			mapI = context.mappings.index((mapping, context))
			mapOff = (
				context.header.mappingWithSlideOffset
				+ mapI * dyld_cache_mapping_and_slide_info.SIZE
			)

			mapping = dyld_cache_mapping_and_slide_info(context.fileCtx.file, mapOff)
			if mapping.slideInfoFileOffset:
				slideInfoVer = context.fileCtx.readFormat(
					"<I",
					mapping.slideInfoFileOffset
				)[0]

				if slideInfoVer not in _SlideInfoMap:
					logger.error("Unknown slide info version: " + slideInfoVer)
					continue

				slideInfo = _SlideInfoMap[slideInfoVer](
					context.fileCtx.file,
					mapping.slideInfoFileOffset
				)
				mappingInfo.append(MappingInfo(mapping, slideInfo, context))
				pass
			pass
		pass

	return mappingInfo


StructureT = TypeVar("StructureT", bound=Structure)


class PointerSlider(object):

	def __init__(self, extractionCtx: ExtractionContext) -> None:
		"""Provides a way to slide individual pointers.
		"""

		super().__init__()

		self._dyldCtx = extractionCtx.dyldCtx
		self._mappingSlidePairs = _getMappingInfo(extractionCtx)

	def slideAddress(self, address: int) -> int:
		"""Slide and return the pointer at the address.

		Args:
			address: The address of the pointer.

		Returns:
			The slide version of the pointer. This will return None if
			the pointer could not be slid.
		"""

		if not (offset := self._dyldCtx.convertAddr(address)):
			return None

		return self.slideOffset(offset)

	def slideOffset(self, offset: int) -> int:
		"""Slide and return the pointer at the file offset.

		Args:
			offset: The file offset.

		Returns:
			The slide version of the pointer. This will return None if
			the pointer could not be slid.
		"""

		for pair in self._mappingSlidePairs:
			mapping = pair[0]
			mappingHighBound = mapping.fileOffset + mapping.size

			if offset >= mapping.fileOffset and offset < mappingHighBound:
				slideInfo = pair[1]

				# regular arm64 pointer
				if slideInfo.version == 2:
					return self._dyldCtx.readFormat(offset, "<Q")[0] & 0xfffffffff

				# arm64e pointer
				elif slideInfo.version == 3:
					ptrInfo = dyld_cache_slide_pointer3(self._dyldCtx.file, offset)
					if ptrInfo.auth.authenticated:
						newValue = ptrInfo.auth.offsetFromSharedCacheBase
						return newValue + slideInfo.auth_value_add
					else:
						value51 = ptrInfo.plain.pointerValue
						top8Bits = value51 & 0x0007F80000000000
						bottom43Bits = value51 & 0x000007FFFFFFFFFF
						return (top8Bits << 13) | bottom43Bits

				else:
					return None

		return None

	def slideStruct(
		self,
		address: int,
		structDef: Type[StructureT]
	) -> StructureT:
		"""Read and slide a structure at the address.

		This will use the _pointers_ class property to
		slide the correct variables. If the structure does
		not have this, nothing will be slid.

		Args:
			address: The address of the structure.
			structure: The structure class to fill.

		Return:
			The filled and slid structure.
		"""

		structOff = self._dyldCtx.convertAddr(address)
		structData = structDef(self._dyldCtx.file, structOff)

		if ptrNames := getattr(structData, "_pointers_", None):
			for ptrName in ptrNames:
				ptrOff = structOff + getattr(structDef, ptrName).offset
				slidPtr = self.slideOffset(ptrOff)
				setattr(structData, ptrName, slidPtr)
				pass
			pass

		return structData


def processSlideInfo(extractionCtx: ExtractionContext) -> None:
	"""Process and remove rebase info.

		Pointers in the Dyld shared cache don't have the usual rebase info
	found in regular MachO files. Instead they put that info in the pointer
	themselves. This results in pointers that look like this 0x800XXXXXXXXXX.

	This removes that info.

	Args:
		dyldCtx: The dyld context
		machoCtx: The MachO context. This must be writable!

	Returns:
		The processed file.
	"""

	logger = extractionCtx.logger

	# get a list of mapping and slide info
	mappingInfo = _getMappingInfo(extractionCtx)
	if not mappingInfo:
		return

	# Process each pair
	for info in mappingInfo:
		if info.slideInfo.version == 2:
			_V2Rebaser(extractionCtx, info).run()
		elif info.slideInfo.version == 3:
			_V3Rebaser(extractionCtx, info).run()
		else:
			logger.error("Unknown slide version.")
