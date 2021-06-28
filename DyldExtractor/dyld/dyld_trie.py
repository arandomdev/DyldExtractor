import logging
import dataclasses
from mmap import mmap

from DyldExtractor import leb128

from DyldExtractor.macho.macho_constants import *


def _readString(file: mmap, readHead: int) -> tuple[bytes, int]:
	"""Read a null terminated string.

	Returns:
		The string including the new read head.
	"""

	nullIndex = file.find(b"\x00", readHead)
	if nullIndex == -1:
		return None

	string = file[readHead:nullIndex + 1]
	readHead += len(string)
	return (string, readHead)


@dataclasses.dataclass
class ExportInfo(object):
	address: int = 0
	flags: int = 0
	other: int = 0
	name: bytes = None

	importName: bytes = None

	def loadData(self, file: mmap, offset: int) -> int:
		self.flags, offset = leb128.decodeUleb128(file, offset)

		if self.flags & EXPORT_SYMBOL_FLAGS_REEXPORT:
			# dylib ordinal
			self.other, offset = leb128.decodeUleb128(file, offset)
			self.importName, offset = _readString(file, offset)

		else:
			self.address, offset = leb128.decodeUleb128(file, offset)

			if self.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER:
				self.other, offset = leb128.decodeUleb128(file, offset)

		return offset


class ExportReaderError(Exception):
	pass


class _ExportTrieReader(object):

	exports: list[ExportInfo]

	def __init__(
		self,
		file: mmap,
		exportOff: int,
		exportSize: int
	) -> None:
		super().__init__()

		self.file = file
		self.start = exportOff
		self.end = exportOff + exportSize

		self.exports = []

		self.cumulativeString = bytearray()
		self._processNode(self.start, 0)
		pass

	def _getCurrentString(self) -> bytes:
		nullTermIndex = self.cumulativeString.index(b"\x00")
		return self.cumulativeString[0:nullTermIndex + 1]

	def _processNode(
		self,
		offset: int,
		curStrOff: int
	) -> None:
		if offset >= self.end:
			raise ExportReaderError("Node Offset extends beyond export end.")

		terminalSize, offset = leb128.decodeUleb128(self.file, offset)

		childrenOff = offset + terminalSize
		if childrenOff >= self.end:
			raise ExportReaderError("Children offset extend beyond export end.")

		if terminalSize:
			exportInfo = ExportInfo()
			exportInfo.name = self._getCurrentString()
			offset = exportInfo.loadData(self.file, offset)

			self.exports.append(exportInfo)

		# process the child nodes
		childrenCount = self.file[childrenOff]
		childrenOff += 1

		for _ in range(childrenCount):
			edgeString, childrenOff = _readString(self.file, childrenOff)
			edgeStrLen = len(edgeString) - 1

			self.cumulativeString[curStrOff:curStrOff + edgeStrLen] = edgeString

			childNodeOff, childrenOff = leb128.decodeUleb128(self.file, childrenOff)
			childNodeOff += self.start

			self._processNode(childNodeOff, curStrOff + edgeStrLen)
		pass


def ReadExports(
	file: mmap,
	exportOff: int,
	exportSize: int
) -> list[ExportInfo]:
	"""Read an export trie.

	Args:
		file: The source file to read from.
		exportOff: The offset into the file to the export trie.
		exportSize: The total size of the export trie.

	Returns:
		A list of ExportInfo

	Raises:
		ExportReaderError: If there was an error reading the export trie.
	"""
	reader = _ExportTrieReader(file, exportOff, exportSize)
	return reader.exports
