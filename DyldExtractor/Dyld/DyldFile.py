from typing import List
from io import BufferedReader

from DyldExtractor.Dyld import DyldStructs


class DyldFile(object):
	"""Wraps and provides info about a dyld file.

	Attributes
	----------
		header : dyld_cache_header

		localSymbolInfo : dyld_cache_local_symbols_info

		slideInfo : dyld_cache_slide_info2

		mappings: List[dyld_cache_image_info]

		images: List[dyld_cache_image_info]
	"""

	header: DyldStructs.dyld_cache_header
	localSymbolInfo: DyldStructs.dyld_cache_local_symbols_info
	slideInfo: DyldStructs.dyld_cache_slide_info2

	mappings: List[DyldStructs.dyld_cache_image_info]
	images: List[DyldStructs.dyld_cache_image_info]

	def __init__(self, dyldFile: BufferedReader) -> None:
		self.file = dyldFile

		self.header = DyldStructs.dyld_cache_header.parse(dyldFile, 0)
		self.localSymbolInfo = DyldStructs.dyld_cache_local_symbols_info.parse(dyldFile, self.header.localSymbolsOffset)
		self.slideInfo = DyldStructs.dyld_cache_slide_info2.parse(dyldFile, self.header.slideInfoOffset)

		self.mappings = []
		for i in range(self.header.mappingCount):
			mappingOff = (i * DyldStructs.dyld_cache_mapping_info.SIZE) + self.header.mappingOffset
			self.mappings.append(DyldStructs.dyld_cache_mapping_info.parse(dyldFile, mappingOff))
		
		self.images = []
		for i in range(self.header.imagesCount):
			imageOff = (i * DyldStructs.dyld_cache_image_info.SIZE) + self.header.imagesOffset
			self.images.append(DyldStructs.dyld_cache_image_info.parse(dyldFile, imageOff))
		pass

	def readString(self, fileOff: int) -> bytes:
		"""Read a C-String.

		Parameters
		----------
			fileOff : int
				The file offset of the C-String.

		Returns
		-------
			bytes
				The null terminated C-String.
		"""

		if fileOff < 0:
			# maybe we should crash here and fix it elsewhere?
			# maybe later, this works fine
			return b''

		self.file.seek(fileOff)
		data = b""
		while True:
			char = self.file.read(1)
			data += char

			if char == b"\x00":
				return data
	
	def convertAddr(self, VMAddr: int) -> int:
		"""Converts a VMAddr to a file offset.

		Parameters
		----------
			VMAddr : int
				The VMAddr.

		Returns
		-------
			int
				The file offset.
		"""
		
		for mapping in self.mappings:
			lowAddrBound = mapping.address
			highAddrBound = mapping.address + mapping.size
			if VMAddr >= lowAddrBound and VMAddr < highAddrBound:
				return (VMAddr - mapping.address) + mapping.fileOffset
		
		return -1