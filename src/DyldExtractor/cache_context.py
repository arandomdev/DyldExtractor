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


class CacheContext(FileContext):

	def __init__(self, fileObject: BinaryIO, copyMode: bool = False) -> None:
		super().__init__(fileObject, copyMode=copyMode)

	def convertAddr(self, vmaddr: int) -> Tuple[int, "CacheContext"]:
		"""Convert a vmaddr to its file offset

		Returns:
			The file offset and the CacheContext, but if not found, `None`.
		"""

		for mapping, ctx in self.mappings:
			lowBound = mapping.address
			highBound = mapping.address + mapping.size

			if vmaddr >= lowBound and vmaddr < highBound:
				mappingOff = vmaddr - lowBound
				return mapping.fileOffset + mappingOff, ctx

		# didn't find the address in any mappings...
		return None

	def hasSubCaches(self) -> bool:
		return False
	
	def isFileset(self) -> bool:
		return False
