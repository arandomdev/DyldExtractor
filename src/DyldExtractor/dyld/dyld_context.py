import pathlib
from typing import (
	List,
	Tuple,
	BinaryIO
)

from DyldExtractor.file_context import FileContext
from DyldExtractor.dyld.dyld_structs import (
	dyld_cache_header,
	dyld_cache_mapping_info,
	dyld_cache_image_info,
	dyld_subcache_entry,
	dyld_subcache_entry2,
)


class DyldContext(FileContext):

	def __init__(self, fileObject: BinaryIO, copyMode: bool = False) -> None:
		"""A wrapper around a dyld file.

		Provides convenient methods and attributes for a given dyld file.

		Args:
			file: an open dyld file. Or the main cache file in the case of
				sub caches.
		"""

		super().__init__(fileObject, copyMode=copyMode)

		self.header = dyld_cache_header(self.file)

		# Check magic
		if self.header.magic[0:4] != b"dyld":
			raise ValueError("Cache's magic does not start with 'dyld', most likely given a file that's not a cache or the file is broken.")  # noqa

		self.mappings: List[Tuple[dyld_cache_mapping_info, DyldContext]] = []
		for i in range(self.header.mappingCount):
			offset = self.header.mappingOffset + (i * dyld_cache_mapping_info.SIZE)
			self.mappings.append((dyld_cache_mapping_info(self.file, offset), self))
			pass

		# get images
		self.images: List[dyld_cache_image_info] = []
		if self.headerContainsField("imagesCount"):
			imagesCount = self.header.imagesCount
			imagesOffset = self.header.imagesOffset
			pass
		else:
			imagesCount = self.header.imagesCountOld
			imagesOffset = self.header.imagesOffsetOld
			pass

		for i in range(imagesCount):
			offset = imagesOffset + (i * dyld_cache_image_info.SIZE)
			self.images.append(dyld_cache_image_info(self.file, offset))
			pass

		self._subCaches: List[DyldContext] = []
		pass

	def convertAddr(self, vmaddr: int) -> Tuple[int, "DyldContext"]:
		"""Convert a vmaddr to its file offset

		Returns:
			The file offset and the DyldContext, but if not found, `None`.
		"""

		for mapping, ctx in self.mappings:
			lowBound = mapping.address
			highBound = mapping.address + mapping.size

			if vmaddr >= lowBound and vmaddr < highBound:
				mappingOff = vmaddr - lowBound
				return mapping.fileOffset + mappingOff, ctx

		# didn't find the address in any mappings...
		return None

	def headerContainsField(self, field: str) -> bool:
		"""Check to see if the header contains the given field.

		Args:
			`field`: The name of the field.

		Returns:
			A bool.
		"""

		# first check to see if we even have it.
		if not hasattr(self.header, field):
			return False

		fieldOff = getattr(dyld_cache_header, field).offset
		mappingOff = self.header.mappingOffset

		# The mapping info is directly after the header. We can use this fact
		# to determine if the header originally had that field.
		if fieldOff < mappingOff:
			return True
		else:
			return False

	def hasSubCaches(self) -> bool:
		"""Check if the dyld cache has sub caches.

		Returns:
			If the cache has subcaches or not. The symbols cache is factored
			into this calculation, but the symbols cache is not counted in
			subCacheArrayCount. It is implicitly included.
		"""

		if (
			self.headerContainsField("subCacheArrayCount")
			and self.header.subCacheArrayCount
		):
			return True

		emptyUUID = b"\x00" * len(self.header.symbolFileUUID)
		if (
			self.headerContainsField("symbolFileUUID")
			and bytes(self.header.symbolFileUUID) != emptyUUID
		):
			return True

		return False

	def addSubCaches(self, mainCachePath: pathlib.Path) -> List[BinaryIO]:
		"""Adds any subcaches.

		Args:
			mainCachePath: Path to the main cache path.
		Returns: A list of file objects that need to be closed.
		"""

		if not self.hasSubCaches():
			return []

		subCacheFiles: List[BinaryIO] = []
		subCacheEntriesStart = self.header.subCacheArrayOffset
		usesV2 = self.header.cacheType == 2
		for i in range(self.header.subCacheArrayCount):
			if usesV2:
				subCacheEntry = dyld_subcache_entry2(
					self.file,
					subCacheEntriesStart + (i * dyld_subcache_entry2.SIZE)
				)
				subCachePath = mainCachePath.with_suffix(
					subCacheEntry.fileExtension.decode("utf-8")
				)
				pass
			else:
				subCacheEntry = dyld_subcache_entry(
					self.file,
					subCacheEntriesStart + (i * dyld_subcache_entry.SIZE)
				)
				# has 1-based index extension
				subCachePath = mainCachePath.with_suffix(f".{i + 1}")
				pass

			subCacheFile = open(subCachePath, mode="rb")
			subCacheFiles.append(subCacheFile)
			subCacheCtx = DyldContext(subCacheFile)
			self._subCaches.append(subCacheCtx)
			self.mappings.extend(subCacheCtx.mappings)
			pass

		if (
			self.headerContainsField("symbolFileUUID")
			and bytes(self.header.symbolFileUUID) != (b"\x00" * 16)
		):
			# Add Symbols Cache
			symbolsCachePath = mainCachePath.with_suffix(".symbols")
			symbolsCacheFile = open(symbolsCachePath, mode="rb")
			subCacheFiles.append(symbolsCacheFile)
			symbolsCacheCtx = DyldContext(symbolsCacheFile)
			self._subCaches.append(symbolsCacheCtx)
			self.mappings.extend(symbolsCacheCtx.mappings)
			pass

		return subCacheFiles

	def getSymbolsCache(self) -> "DyldContext":
		"""Get the .symbols cache.

		Try to find the .symbols cache by matching uuids.
		If there are no sub caches, this just returns itself.
		Or None if the .symbols cache cannot be found.
		"""

		if not self._subCaches or not self.headerContainsField("symbolFileUUID"):
			return self

		for cache in self._subCaches:
			if bytes(self.header.symbolFileUUID) == bytes(cache.header.uuid):
				return cache
			pass

		return None
