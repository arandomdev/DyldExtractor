from __future__ import annotations

import logging
from io import BufferedReader
from enum import IntEnum
from typing import ClassVar, List
from DyldExtractor.Structure import Structure


__all__ = [
	"Slide",
	"dyld_cache_header",
	"dyld_cache_image_info",
	"dyld_cache_local_symbols_entry",
	"dyld_cache_local_symbols_info",
	"dyld_cache_mapping_info",
	"dyld_cache_slide_info2",
	"dyld_cache_slide_info3",
	"dyld_cache_mapping_and_slide_info",
	"dyld_cache_slide_pointer3_plain",
	"dyld_cache_slide_pointer3_auth",
	"dyld_cache_slide_pointer3"
]


class Slide(IntEnum):
	DYLD_CACHE_SLIDE_PAGE_ATTRS = 0xC000 			# high bits of uint16_t are flags
	DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA = 0x8000 		# index is into extras array (not starts array)
	DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE = 0x4000 	# page has no rebasing
	DYLD_CACHE_SLIDE_PAGE_ATTR_END = 0x8000 		# last chain entry for page

	DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE = 0xFFF # page has no rebasing


class dyld_cache_header(Structure):
	
	headerType: int

	magic: bytes					# e.g. "dyld_v0    i386"
	mappingOffset: int				# file offset to first dyld_cache_mapping_info
	mappingCount: int				# number of dyld_cache_mapping_info entries
	imagesOffset: int				# file offset to first dyld_cache_image_info
	imagesCount: int				# number of dyld_cache_image_info entries
	dyldBaseAddress: int			# base address of dyld when cache was built
	codeSignatureOffset: int		# file offset of code signature blob
	codeSignatureSize: int			# size of code signature blob (zero means to end of file)
	slideInfoOffset: int			# file offset of kernel slid info
	slideInfoSize: int				# size of kernel slid info
	localSymbolsOffset: int			# file offset of where local symbols are stored
	localSymbolsSize: int			# size of local symbols information
	uuid: bytes						# unique value for each shared cache file
	cacheType: int					# 0 for development, 1 for production
	branchPoolsOffset: int			# file offset to table of uint64_t pool addresses
	branchPoolsCount: int			# number of uint64_t entries
	accelerateInfoAddr: int			# (unslid) address of optimization info
	accelerateInfoSize: int			# size of optimization info
	imagesTextOffset: int			# file offset to first dyld_cache_image_text_info
	imagesTextCount: int			# number of dyld_cache_image_text_info entries
	patchInfoAddr: int 				# (unslid) address of dyld_cache_patch_info
	patchInfoSize: int 				# Size of all of the patch information pointed to via the dyld_cache_patch_info
	otherImageGroupAddrUnused: int 	# unused
	otherImageGroupSizeUnused: int 	# unused
	progClosuresAddr: int 			# (unslid) address of list of program launch closures
	progClosuresSize: int 			# size of list of program launch closures
	progClosuresTrieAddr: int 		# (unslid) address of trie of indexes into program launch closures
	progClosuresTrieSize: int 		# size of trie of indexes into program launch closures
	platform: int 					# platform number (macOS=1, etc)
	CacheInfoBitfield: int 			# a bitfield
		# formatVersion          : 8,  # dyld3::closure::kFormatVersion
		# dylibsExpectedOnDisk   : 1,  # dyld should expect the dylib exists on disk and to compare inode/mtime to see if cache is valid
		# simulator              : 1,  # for simulator of specified platform
		# locallyBuiltCache      : 1,  # 0 for B&I built cache, 1 for locally built cache
		# builtFromChainedFixups : 1,  # some dylib in cache was built using chained fixups, so patch tables must be used for overrides
		# padding                : 20; # TBD
	sharedRegionStart: int 			# base load address of cache if not slid
	sharedRegionSize: int 			# overall size of region cache can be mapped into
	maxSlide: int 					# runtime slide of cache can be between zero and this value
	dylibsImageArrayAddr: int 		# (unslid) address of ImageArray for dylibs in this cache
	dylibsImageArraySize: int 		# size of ImageArray for dylibs in this cache
	dylibsTrieAddr: int 			# (unslid) address of trie of indexes of all cached dylibs
	dylibsTrieSize: int 			# size of trie of cached dylib paths
	otherImageArrayAddr: int 		# (unslid) address of ImageArray for dylibs and bundles with dlopen closures
	otherImageArraySize: int 		# size of ImageArray for dylibs and bundles with dlopen closures
	otherTrieAddr: int 				# (unslid) address of trie of indexes of all dylibs and bundles with dlopen closures
	otherTrieSize: int 				# size of trie of dylibs and bundles with dlopen closures	
	mappingWithSlideOffset: int 	# file offset to first dyld_cache_mapping_and_slide_info
	mappingWithSlideCount: int 		# number of dyld_cache_mapping_and_slide_info entries

	_fields_ = (
		("magic", 16),
		("mappingOffset", "<I"),
		("mappingCount", "<I"),
		("imagesOffset", "<I"),
		("imagesCount", "<I"),
		("dyldBaseAddress", "<Q"),
		("codeSignatureOffset", "<Q"),
		("codeSignatureSize", "<Q"),
		("slideInfoOffset", "<Q"),
		("slideInfoSize", "<Q"),
		("localSymbolsOffset", "<Q"),
		("localSymbolsSize", "<Q"),
		("uuid", 16),
		("cacheType", "<Q"),
		("branchPoolsOffset", "<I"),
		("branchPoolsCount", "<I"),
		("accelerateInfoAddr", "<Q"),
		("accelerateInfoSize", "<Q"),
		("imagesTextOffset", "<Q"),
		("imagesTextCount", "<Q"),
		("patchInfoAddr", "<Q"),
		("patchInfoSize", "<Q"),
		("otherImageGroupAddrUnused", "<Q"),
		("otherImageGroupSizeUnused", "<Q"),
		("progClosuresAddr", "<Q"),
		("progClosuresSize", "<Q"),
		("progClosuresTrieAddr", "<Q"),
		("progClosuresTrieSize", "<Q"),
		("platform", "<I"),
		("CacheInfoBitfield", "<I"),
		("sharedRegionStart", "<Q"),
		("sharedRegionSize", "<Q"),
		("maxSlide", "<Q"),
		("dylibsImageArrayAddr", "<Q"),
		("dylibsImageArraySize", "<Q"),
		("dylibsTrieAddr", "<Q"),
		("dylibsTrieSize", "<Q"),
		("otherImageArrayAddr", "<Q"),
		("otherImageArraySize", "<Q"),
		("otherTrieAddr", "<Q"),
		("otherTrieSize", "<Q"),
		("mappingWithSlideOffset", "<I"),
		("mappingWithSlideCount", "<I"),
	)

	@classmethod
	def parse(cls, buffer: BufferedReader, fileOffset: int, loadData: bool = True) -> dyld_cache_header:
		inst = super().parse(buffer, fileOffset, loadData=loadData)

		# The mappingOffset is directly after this header, because of that
		# we can determine the correct size of this
		search = lambda field: inst.offsetOf(field[0]) == inst.mappingOffset
		fieldCutoff = next(filter(search, inst._fields_), None)

		if inst.mappingOffset == 0x140:
			inst.cutoffPoint = -1
		elif not fieldCutoff:
			logging.warning("Unable to determine dyld_cache_header length")
			inst.cutoffPoint = -1
		else:
			# zero out the unused fields
			inst.cutoffPoint = inst._fields_.index(fieldCutoff)
			targetFields = inst._fields_[inst.cutoffPoint:]
			for field in targetFields:
				setattr(inst, field[0], None)

		return inst
	
	def containsField(self, field: str) -> bool:
		"""Check that a field is available within the header.

		args:
			field: the field to check
		"""

		fieldIndex = -1
		for f in self._fields_:
			if f[0] == field:
				fieldIndex = self._fields_.index(f)
				break
		
		if fieldIndex == -1:
			return False

		if self.cutoffPoint -1:
			return True
		
		if fieldIndex >= self.cutoffPoint:
			return False
		else:
			return True

	def asBytes(self) -> bytes:
		data = super().asBytes()

		# delete data after the cutoff point
		cutoffIndex = self.offsetOf(self._fields_[self.cutoffPoint])
		data = data[0:cutoffIndex]

		return data


class dyld_cache_mapping_info(Structure):
	
	SIZE: ClassVar[int] = 32

	address: int
	size: int
	fileOffset: int
	maxProt: int
	initProt: int

	_fields_ = (
		("address", "<Q"),
		("size", "<Q"),
		("fileOffset", "<Q"),
		("maxProt", "<I"),
		("initProt", "<I"),
	)


class dyld_cache_image_info(Structure):
	
	SIZE: ClassVar[int] = 32

	address: int
	modTime: int
	inode: int
	pathFileOffset: int
	pad: int

	_fields_ = (
		("address", "<Q"),
		("modTime", "<Q"),
		("inode", "<Q"),
		("pathFileOffset", "<I"),
		("pad", "<I"),
	)


class dyld_cache_slide_info2(Structure):
	
	version: int			# currently 2
	page_size: int			# currently 4096 (may also be 16384)
	page_starts_offset: int
	page_starts_count: int
	page_extras_offset: int
	page_extras_count: int
	delta_mask: int			# which (contiguous) set of bits contains the delta to the next rebase location
	value_add: int

	# uint16_t	page_starts[page_starts_count];
	# uint16_t	page_extras[page_extras_count];

	pageStartsData: bytes
	pageExtrasData: bytes

	_fields_ = (
		("version", "<I"),
		("page_size", "<I"),
		("page_starts_offset", "<I"),
		("page_starts_count", "<I"),
		("page_extras_offset", "<I"),
		("page_extras_count", "<I"),
		("delta_mask", "<Q"),
		("value_add", "<Q"),
	)

	def loadData(self) -> None:
		self._buffer.seek(self._offset + self.page_starts_offset)
		self.pageStartsData = self._buffer.read(self.page_starts_count * 2)

		self._buffer.seek(self._offset + self.page_extras_offset)
		self.pageExtrasData = self._buffer.read(self.page_extras_count * 2)


class dyld_cache_slide_info3(Structure):
	version: int 			# currently 3
	page_size: int 			# currently 4096 (may also be 16384)
	page_starts_count: int
	auth_value_add: int

	# page_starts[/* page_starts_count */]
	pageStartsData: bytes

	_fields_ = (
		("version", "<I"),
		("page_size", "<I"),
		("page_starts_count", "<I"),
		("auth_value_add", "<Q"),
	)

	def loadData(self) -> None:
		self._buffer.seek(self._offset + self.size)
		self.pageStartsData = self._buffer.read(self.page_starts_count * 2)
		pass


class dyld_cache_local_symbols_entry(Structure):

	SIZE: ClassVar[int] = 12

	dylibOffset: int 		# offset in cache file of start of dylib
	nlistStartIndex: int 	# start index of locals for this dylib
	nlistCount: int 		# number of local symbols for this dylib

	_fields_ = (
		("dylibOffset", "<I"),
		("nlistStartIndex", "<I"),
		("nlistCount", "<I"),
	)


class dyld_cache_local_symbols_info(Structure):
	
	nlistOffset: int 	# offset into this chunk of nlist entries
	nlistCount: int 	# count of nlist entries
	stringsOffset: int 	# offset into this chunk of string pool
	stringsSize: int 	# byte count of string pool
	entriesOffset: int 	# offset into this chunk of array of dyld_cache_local_symbols_entry 
	entriesCount: int 	# number of elements in dyld_cache_local_symbols_entry array

	nlistData: bytes
	stringData: bytes

	entries: List[dyld_cache_local_symbols_entry]

	_fields_ = (
		("nlistOffset", "<I"),
		("nlistCount", "<I"),
		("stringsOffset", "<I"),
		("stringsSize", "<I"),
		("entriesOffset", "<I"),
		("entriesCount", "<I"),
	)

	def loadData(self) -> None:
		self._buffer.seek(self._offset + self.nlistOffset)
		self.nlistData = self._buffer.read(self.nlistCount * 16) # size of nlist_64
		self._buffer.seek(self._offset + self.stringsOffset)
		self.stringData = self._buffer.read(self.stringsSize)

		self.entries = []
		for i in range(0, self.entriesCount):
			offset = (i * dyld_cache_local_symbols_entry.SIZE) + self._offset + self.entriesOffset
			self.entries.append(dyld_cache_local_symbols_entry.parse(self._buffer, offset))


class dyld_cache_mapping_and_slide_info(Structure):

	SIZE: ClassVar[int] = 56
	
	address: int
	size: int
	fileOffset: int
	slideInfoFileOffset: int
	slideInfoFileSize: int
	flags: int
	maxProt: int
	initProt: int

	_fields_ = (
		("address", "<Q"),
		("size", "<Q"),
		("fileOffset", "<Q"),
		("slideInfoFileOffset", "<Q"),
		("slideInfoFileSize", "<Q"),
		("flags", "<Q"),
		("maxProt", "<I"),
		("initProt", "<I"),
	)


class dyld_cache_slide_pointer3_plain(object):
	"""Represents a plain pointer"""

	pointerValue: int
	offsetToNextPointer: int
	unused: int

	def __init__(self, raw: int) -> None:
		self.pointerValue = raw % 0x7FFFFFFFFFFFF
		self.offsetToNextPointer = (raw >> 51) & 0x7FF
		self.unused = raw >> 62


class dyld_cache_slide_pointer3_auth(object):
	"""Represents an authenticated pointer"""

	offsetFromSharedCacheBase: int
	diversityData: int
	hasAddressDiversity: int
	key: int
	offsetToNextPointer: int
	unused: int
	authenticated: int 				# = 1

	def __init__(self, raw) -> None:
		self.offsetFromSharedCacheBase = raw & 0xFFFFFFFF
		self.diversityData = (raw >> 32) & 0xFFFF
		self.hasAddressDiversity = (raw >> 48) & 0x1
		self.key = (raw >> 49) & 0x3
		self.offsetToNextPointer = (raw >> 51) & 0x7FF
		self.unused = (raw >> 62) & 0x1
		self.authenticated = raw >> 63


class dyld_cache_slide_pointer3(Structure):
	"""Represents an unslid V3 rebase pointer.
	
	This structure is STRICTLY immutable!
	"""

	raw: int

	_fields_ = (
		("raw", "<Q"),
	)

	plain: dyld_cache_slide_pointer3_plain
	auth: dyld_cache_slide_pointer3_auth

	def loadData(self) -> None:
		super().loadData()

		self.plain = dyld_cache_slide_pointer3_plain(self.raw)
		self.auth = dyld_cache_slide_pointer3_auth(self.raw)