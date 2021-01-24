from typing import ClassVar, List
from enum import IntEnum

from DyldExtractor.Structure import Structure


__all__ = [
	"Slide",
	"dyld_cache_header",
	"dyld_cache_image_info",
	"dyld_cache_local_symbols_entry",
	"dyld_cache_local_symbols_info",
	"dyld_cache_mapping_info",
	"dyld_cache_slide_info2"
]


class Slide(IntEnum):
	DYLD_CACHE_SLIDE_PAGE_ATTRS = 0xC000 			# high bits of uint16_t are flags
	DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA = 0x8000 		# index is into extras array (not starts array)
	DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE = 0x4000 	# page has no rebasing
	DYLD_CACHE_SLIDE_PAGE_ATTR_END = 0x8000 		# last chain entry for page


class dyld_cache_header(Structure):
	
	headerType: int

	# headerType = 1 (dyld-95.3)
	magic: bytes				# e.g. "dyld_v0    i386"
	mappingOffset: int			# file offset to first dyld_cache_mapping_info
	mappingCount: int			# number of dyld_cache_mapping_info entries
	imagesOffset: int			# file offset to first dyld_cache_image_info
	imagesCount: int			# number of dyld_cache_image_info entries
	dyldBaseAddress: int		# base address of dyld when cache was built
	
	# headerType = 2 (dyld-195.5)
	codeSignatureOffset: int	# file offset of code signature blob
	codeSignatureSize: int		# size of code signature blob (zero means to end of file)
	slideInfoOffset: int		# file offset of kernel slid info
	slideInfoSize: int			# size of kernel slid info
	
	# headerType = 3 (No header file for this version (without the following UUID), but there are images of this version)
	localSymbolsOffset: int		# file offset of where local symbols are stored
	localSymbolsSize: int		# size of local symbols information
	
	# headerType = 4 (dyld-239.3)
	uuid: bytes					# unique value for each shared cache file
	
	# headerType = 5 (dyld-360.14)
	cacheType: int				# 0 for development, 1 for production
	
	# headerType = 6 (dyld-421.1)
	branchPoolsOffset: int		# file offset to table of uint64_t pool addresses
	branchPoolsCount: int		# number of uint64_t entries
	accelerateInfoAddr: int		# (unslid) address of optimization info
	accelerateInfoSize: int		# size of optimization info
	imagesTextOffset: int		# file offset to first dyld_cache_image_text_info
	imagesTextCount: int		# number of dyld_cache_image_text_info entries

	# headerType = 7 (dyld-832.7.1)
	patchInfoAddr: int 				# (unslid) address of dyld_cache_patch_info
	patchInfoSize: int 				# Size of all of the patch information pointed to via the dyld_cache_patch_info
	otherImageGroupAddrUnused: int 	# unused
	otherImageGroupSizeUnused: int 	# unused
	progClosuresAddr: int 			# (unslid) address of list of program launch closures
	progClosuresSize: int 			# size of list of program launch closures
	progClosuresTrieAddr: int 		# (unslid) address of trie of indexes into program launch closures
	progClosuresTrieSize: int 		# size of trie of indexes into program launch closures
	platform: int 					# platform number (macOS=1, etc)

	CacheInformation: int 			# a bitfield
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
		("CacheInformation", "<I"),
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
		# self._buffer.seek(self._offset + self.size)
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