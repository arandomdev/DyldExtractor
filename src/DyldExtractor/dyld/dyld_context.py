from typing import List, Tuple

from DyldExtractor.file_context import FileContext
from DyldExtractor.dyld.dyld_structs import (
	dyld_cache_header,
	dyld_cache_mapping_info,
	dyld_cache_image_info,
)


class DyldContext(object):

	def __init__(self, file: FileContext) -> None:
		"""A wrapper around a dyld file.

		Provides convenient methods and attributes for a given dyld file.

		Args:
			file: an open dyld file. Or the main cache file in the case of
				sub caches.
		"""

		super().__init__()

		self.fileCtx = file
		self.header = dyld_cache_header(file.file)

		self.mappings: List[Tuple[dyld_cache_mapping_info, DyldContext]] = []
		for i in range(self.header.mappingCount):
			offset = self.header.mappingOffset + (i * dyld_cache_mapping_info.SIZE)
			self.mappings.append((dyld_cache_mapping_info(file.file, offset), self))
			pass

		# get images
		self.images: List[dyld_cache_image_info] = []
		if self.headerContainsField("imagesCountWithSubCaches"):
			imagesCount = self.header.imagesCountWithSubCaches
			imagesOffset = self.header.imagesOffsetWithSubCaches
			pass
		else:
			imagesCount = self.header.imagesCount
			imagesOffset = self.header.imagesOffset
			pass

		for i in range(imagesCount):
			offset = imagesOffset + (i * dyld_cache_image_info.SIZE)
			self.images.append(dyld_cache_image_info(file.file, offset))
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
		"""

		if self.headerContainsField("numSubCaches") and self.header.numSubCaches:
			return True
		else:
			return False

	def addSubCaches(self, subCacheFileCtxs: list[FileContext]) -> None:
		cacheClass = type(self)
		for fileCtx in subCacheFileCtxs:
			subCache = cacheClass(fileCtx)
			self._subCaches.append(subCache)
			self.mappings.extend(subCache.mappings)
			pass
		pass

	def getSymbolsCache(self) -> "DyldContext":
		"""Get the .symbols cache.

		Try to find the .symbols cache by matching uuids.
		If there are no sub caches, this just returns itself.
		Or None if the .symbols cache cannot be found.
		"""

		if not self._subCaches:
			return self

		for cache in self._subCaches:
			if self.header.symbolSubCacheUUID == cache.header.uuid:
				return cache
			pass

		return None
