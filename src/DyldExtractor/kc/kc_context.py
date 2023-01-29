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

from DyldExtractor.macho.macho_context import MachOContext
from DyldExtractor.cache_context import CacheContext

from DyldExtractor.macho.macho_structs import (
	LoadCommandMap,
	LoadCommands,
	load_command,
	UnknownLoadCommand,
	mach_header_64,
	segment_command_64
)

class KCContext(CacheContext):

	def __init__(self, fileObject: BinaryIO, copyMode: bool = False) -> None:
		"""A wrapper around a kernelcache file.

		Provides convenient methods and attributes for a given kernelcache file.

		Args:
			file: an open kernelcache file.
		"""

		super().__init__(fileObject, copyMode=copyMode)
		
		machoCtx = MachOContext(fileObject, 0, False)
		self._machoCtx = machoCtx
		self.header = machoCtx.header

		# Check filetype
		MH_FILESET = 0xc
		if self.header.filetype != MH_FILESET:
			raise Exception("Only MH_FILESET kernelcaches are supported!")

		self.mappings: List[Tuple[dyld_cache_mapping_info, KCContext]] = []
		for segment in machoCtx.segmentsI:
			seg = segment.seg

			info = dyld_cache_mapping_info()
			info.address = seg.vmaddr
			info.size = seg.vmsize
			info.fileOffset = seg.fileoff
			self.mappings.append((info, self))
			pass

		# get images
		self.images: List[dyld_cache_image_info] = []

		filesetEntries = machoCtx.getLoadCommand((LoadCommands.LC_FILESET_ENTRY,), multiple=True)
		if not filesetEntries:
			raise Exception("Kernelcache does not contain any fileset entries!")

		for entry in filesetEntries:
			info = dyld_cache_image_info()
			info.pathFileOffset = entry._fileOff_ + entry.entry_id.offset
			info.address = entry.vmaddr
			self.images.append(info)
			pass
		pass

	def isFileset(self) -> bool:
		return True
