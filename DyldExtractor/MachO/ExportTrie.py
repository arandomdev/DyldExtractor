from typing import List

from DyldExtractor import Uleb128
from DyldExtractor.MachO.MachoStructs import Export


__all__ = [
	"TrieEntry",
	"TrieParser"
]


class TrieEntry(object):
	"""
	Represents an entry in the export trie.
	"""
	
	nodeOffset: int
	name: bytes
	address: int		# 64bit
	flags: int			# 64bit
	other: int			# 64bit
	importName: bytes
	pass


class TrieParser(object):
	"""
	Reads and parses the export trie.
	"""

	def __init__(self, exportData: bytes) -> None:
		self.exports = exportData
		self.entries = []

		self.cumulativeStr = bytearray()
		pass

	def parse(self) -> List[TrieEntry]:
		"""Parse the trie and get a list of trie entries.

		Returns
		-------
			List[TrieEntry]
				A list of entries.
		"""

		if len(self.exports) != 0:
			self.processNode(0, 0)

		self.entries.sort(key=lambda x: x.nodeOffset)
		return self.entries

	def processNode(self, exportOff: int, cumStrHead: int) -> None:
		"""Recursively process a node.

		Parameters
		----------
			exportOff : int
				The offset in the export data to the node.
			cumStrHead : int
				The end of the string in the cumulative string,
				not including the null byte.

		Raises
		------
			Exception
				raises "Export off beyond export length" if the
				exportOff is beyond the length of the export data.
		"""

		if exportOff >= len(self.exports):
			raise Exception("Export off beyond export length")

		# read the entry
		entryReadHead = exportOff

		terminalSize, ulebSize = Uleb128.readUleb128(self.exports, entryReadHead)
		entryReadHead += ulebSize

		if terminalSize != 0:
			entry = TrieEntry()
			entry.nodeOffset = exportOff

			currentStrEnd = self.cumulativeStr.index(b"\x00") + 1
			entry.name = bytes(self.cumulativeStr[0:currentStrEnd])

			entry.flags, ulebSize = Uleb128.readUleb128(self.exports, entryReadHead)
			entryReadHead += ulebSize

			if entry.flags & Export.EXPORT_SYMBOL_FLAGS_REEXPORT:
				entry.address = 0

				entry.other, ulebSize = Uleb128.readUleb128(self.exports, entryReadHead)
				entryReadHead += ulebSize

				importNameEnd = self.exports.index(b"\x00", entryReadHead) + 1
				entry.importName = bytes(self.exports[entryReadHead:importNameEnd])
			else:
				entry.address, ulebSize = Uleb128.readUleb128(self.exports, entryReadHead)
				entryReadHead += ulebSize

				entry.importName = None

				if entry.flags & Export.EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER:
					entry.other, ulebSize = Uleb128.readUleb128(self.exports, entryReadHead)
					entryReadHead += ulebSize
				else:
					entry.other = 0
			
			self.entries.append(entry)

		# process children
		childrenCount = int(self.exports[exportOff + terminalSize + 1])
		childrenReadHead = exportOff + terminalSize + 2

		for _ in range(0, childrenCount):
			# read the extra chars
			edgeStrEnd = self.exports.index(b"\x00", childrenReadHead) + 1
			edgeStr = self.exports[childrenReadHead:edgeStrEnd]
			childrenReadHead += len(edgeStr)

			self.cumulativeStr[cumStrHead:] = edgeStr

			# process child
			childNodeOff, ulebSize = Uleb128.readUleb128(self.exports, childrenReadHead)
			childrenReadHead += ulebSize
			
			self.processNode(childNodeOff, cumStrHead + (len(edgeStr) - 1))
		pass