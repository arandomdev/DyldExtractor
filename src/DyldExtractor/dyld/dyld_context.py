from mmap import mmap

from DyldExtractor.file_context import FileContext
from DyldExtractor.dyld.dyld_structs import (
	dyld_cache_header,
	dyld_cache_mapping_info,
	dyld_cache_image_info,
)


class DyldContext(FileContext):

	header: dyld_cache_header
	mappings: list[dyld_cache_mapping_info]
	images: list[dyld_cache_image_info]

	def __init__(self, file: mmap) -> None:
		"""A wrapper around a dyld file.

		Provides convenient methods and attributes for a given dyld file.

		Args:
			file: an open dyld file.
		"""

		super().__init__(file, offset=0)

		self.header = dyld_cache_header(file)

		self.mappings = []
		for i in range(self.header.mappingCount):
			offset = self.header.mappingOffset + (i * dyld_cache_mapping_info.SIZE)
			self.mappings.append(dyld_cache_mapping_info(file, offset))

		self.images = []
		for i in range(self.header.imagesCount):
			offset = self.header.imagesOffset + (i * dyld_cache_image_info.SIZE)
			self.images.append(dyld_cache_image_info(file, offset))
		pass

	def convertAddr(self, vmaddr: int) -> int:
		"""Convert a vmaddr to its file offset

		Returns:
			The file offset, but if not found, `-1`.
		"""

		for mapping in self.mappings:
			lowBound = mapping.address
			highBound = mapping.address + mapping.size

			if vmaddr >= lowBound and vmaddr < highBound:
				mappingOff = vmaddr - lowBound
				return mapping.fileOffset + mappingOff

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
