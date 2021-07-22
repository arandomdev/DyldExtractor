import struct
from typing import (
	Type,
	TypeVar,
	Union,
)

from DyldExtractor.extraction_context import ExtractionContext
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


class _V2Rebaser(object):

	def __init__(
		self,
		extractionCtx: ExtractionContext,
		mapping: dyld_cache_mapping_info,
		slideInfo: dyld_cache_slide_info2
	) -> None:
		super().__init__()

		self.statusBar = extractionCtx.statusBar
		self.dyldCtx = extractionCtx.dyldCtx
		self.machoCtx = extractionCtx.machoCtx
		self.logger = extractionCtx.logger

		self.mapping = mapping
		self.slideInfo = slideInfo

	def run(self) -> None:
		"""Process all slide info.
		"""

		self.statusBar.update(unit="Slide Info Rebaser")

		# get pageStarts, an array of uint_16
		pageStartOff = self.slideInfo._fileOff_ + self.slideInfo.page_starts_offset
		self.dyldCtx.file.seek(pageStartOff)
		pageStarts = self.dyldCtx.file.read(self.slideInfo.page_starts_count * 2)
		pageStarts = [page[0] for page in struct.iter_unpack("<H", pageStarts)]

		for segment in self.machoCtx.segmentsI:
			self._rebaseSegment(pageStarts, segment.seg)

	def _rebaseSegment(
		self,
		pageStarts: tuple[int],
		segment: segment_command_64
	) -> None:
		"""Process all slide info for a segment"""

		# check if the segment is included in the mapping
		if not (
			segment.vmaddr >= self.mapping.address
			and segment.vmaddr < self.mapping.address + self.mapping.size
		):
			return

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
				self._rebasePage(pageOff, page * 4)

				self.statusBar.update(status="Rebasing Pages")
		pass

	def _rebasePage(self, pageStart: int, pageOffset: int) -> None:
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

			rawValue = self.dyldCtx.readFormat(loc, "<Q")[0]
			delta = (rawValue & deltaMask) >> deltaShift

			newValue = rawValue & valueMask
			if valueMask != 0:
				newValue += valueAdd

			self.machoCtx.file[loc:loc + 8] = struct.pack("<Q", newValue)
			pageOffset += delta
		pass
	pass


class _V3Rebaser(object):

	def __init__(
		self,
		extractionCtx: ExtractionContext,
		mapping: dyld_cache_mapping_info,
		slideInfo: dyld_cache_slide_info3
	) -> None:
		super().__init__()

		self.statusBar = extractionCtx.statusBar
		self.dyldCtx = extractionCtx.dyldCtx
		self.machoCtx = extractionCtx.machoCtx
		self.mapping = mapping
		self.slideInfo = slideInfo

	def run(self) -> None:
		self.statusBar.update(unit="Slide Info Rebaser")

		pageStartsOff = self.slideInfo._fileOff_ + len(self.slideInfo)
		self.dyldCtx.file.seek(pageStartsOff)
		pageStarts = self.dyldCtx.file.read(self.slideInfo.page_starts_count * 2)
		pageStarts = [page[0] for page in struct.iter_unpack("<H", pageStarts)]

		for segment in self.machoCtx.segmentsI:
			self._rebaseSegment(pageStarts, segment.seg)

	def _rebaseSegment(
		self,
		pageStarts: tuple[int],
		segment: segment_command_64
	) -> None:
		# check if the segment is included in the mapping
		if not (
			segment.vmaddr >= self.mapping.address
			and segment.vmaddr < self.mapping.address + self.mapping.size
		):
			return

		# get the indices of relevent pageStarts
		dataStart = self.mapping.address
		pageSize = self.slideInfo.page_size

		startAddr = segment.vmaddr - dataStart
		startIndex = int(startAddr / pageSize)

		endAddr = ((segment.vmaddr + segment.vmsize) - dataStart) + pageSize
		endIndex = int(endAddr / pageSize)

		for i in range(startIndex, endIndex):
			page = pageStarts[i]

			if page == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE:
				continue
			else:
				pageOff = (i * pageSize) + self.mapping.fileOffset
				self._rebasePage(pageOff, page)

				self.statusBar.update(status="Rebasing Pages")
		pass

	def _rebasePage(self, pageOffset, delta) -> None:
		locOff = pageOffset

		while True:
			locOff += delta
			locInfo = dyld_cache_slide_pointer3(self.dyldCtx.file, locOff)

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

			self.machoCtx.file[locOff:locOff + 8] = struct.pack("<Q", newValue)

			if delta == 0:
				break


def _getMappingSlidePairs(
	extractionCtx: ExtractionContext
) -> list[tuple[Union[dyld_cache_mapping_info, dyld_cache_slide_info2]]]:
	dyldCtx = extractionCtx.dyldCtx
	logger = extractionCtx.logger

	mappingSlidePairs = []

	if dyldCtx.header.slideInfoOffsetUnused:
		# the version is encoded as the first uint32 field
		slideInfoOff = dyldCtx.header.slideInfoOffsetUnused
		dyldCtx.file.seek(slideInfoOff)
		slideInfoVersion = struct.unpack("<I", dyldCtx.file.read(4))[0]

		if slideInfoVersion not in _SlideInfoMap:
			logger.error("Unknown slide info version: " + slideInfoVersion)
			return None

		# Assume that only the second mapping has slide info
		mapping = dyldCtx.mappings[1]
		slideInfo = _SlideInfoMap[slideInfoVersion](dyldCtx.file, slideInfoOff)
		mappingSlidePairs.append((mapping, slideInfo))

	elif dyldCtx.headerContainsField("mappingWithSlideOffset"):
		# slide info is now in different location
		for i in range(dyldCtx.header.mappingWithSlideCount):
			mappingOff = dyldCtx.header.mappingWithSlideOffset
			mappingOff += i * dyld_cache_mapping_and_slide_info.SIZE

			mapping = dyld_cache_mapping_and_slide_info(dyldCtx.file, mappingOff)
			if mapping.slideInfoFileOffset:
				dyldCtx.file.seek(mapping.slideInfoFileOffset)
				slideInfoVersion = struct.unpack("<I", dyldCtx.file.read(4))[0]

				if slideInfoVersion not in _SlideInfoMap:
					logger.error(f"Unknown slide info version: {slideInfoVersion}")
					continue

				slideInfoStruct = _SlideInfoMap[slideInfoVersion]
				slideInfo = slideInfoStruct(dyldCtx.file, mapping.slideInfoFileOffset)

				mappingSlidePairs.append((mapping, slideInfo))
	else:
		logger.error("Unable to get slide info!")
		return None

	return mappingSlidePairs


StructureT = TypeVar("StructureT", bound=Structure)


class PointerSlider(object):

	def __init__(self, extractionCtx: ExtractionContext) -> None:
		"""Provides a way to slide individual pointers.
		"""

		super().__init__()

		self._dyldCtx = extractionCtx.dyldCtx
		self._mappingSlidePairs = _getMappingSlidePairs(extractionCtx)

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
	mappingSlidePairs = _getMappingSlidePairs(extractionCtx)
	if not mappingSlidePairs:
		return

	# Process each pair
	for pair in mappingSlidePairs:
		if pair[1].version == 2:
			_V2Rebaser(extractionCtx, pair[0], pair[1]).run()
		elif pair[1].version == 3:
			_V3Rebaser(extractionCtx, pair[0], pair[1]).run()
		else:
			logger.error("Unknown slide version.")
