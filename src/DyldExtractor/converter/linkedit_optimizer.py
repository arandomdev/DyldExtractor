import struct
from typing import Union, Type, Dict

from DyldExtractor.dyld.dyld_context import DyldContext
from DyldExtractor.extraction_context import ExtractionContext
from DyldExtractor.builder.linkedit_builder import LinkeditBuilder

from DyldExtractor.dyld.dyld_structs import (
	dyld_cache_local_symbols_info,
	dyld_cache_local_symbols_entry,
	dyld_cache_local_symbols_entry2
)

from DyldExtractor.macho.macho_constants import *
from DyldExtractor.macho.macho_structs import nlist_64


class _SymbolContext(object):

	symbolsSize: int

	def __init__(self) -> None:
		super().__init__()

		self.symbolsSize = 0

		self._stringMap: Dict[bytes, int] = {}
		self._stringLength = 0

		# first string is \x00 historically
		self._stringMap[b"\x00"] = 0
		self._stringLength += 1

	def addString(self, string: bytes) -> int:
		"""Add the string to the string pool.

		Args:
			string: The string to add.

		Returns:
			The index into the pool where the string was added to.
		"""

		if string in self._stringMap:
			return self._stringMap[string]

		else:
			index = self._stringLength

			self._stringLength += len(string)
			self._stringMap[string] = index

			return index

	def compileStrings(self) -> bytes:
		"""Compile and get the string pool.
		"""

		strings = self._stringMap.items()
		strings = sorted(strings, key=lambda item: item[1])  # just in case

		return b"".join(map(lambda item: item[0], strings))


class _LinkeditOptimizer(object):

	def __init__(self, extractionCtx: ExtractionContext) -> None:
		super().__init__()

		self._extractionCtx = extractionCtx
		self._machoCtx = extractionCtx.machoCtx
		self._dyldCtx = extractionCtx.dyldCtx
		self._statusBar = extractionCtx.statusBar
		self._logger = extractionCtx.logger

		self._symbolCtx = _SymbolContext()

		# Create the linkedit builder
		self._linkeditBuilder = LinkeditBuilder(extractionCtx.machoCtx)
		self._linkeditCtx = self._machoCtx.ctxForAddr(
			self._machoCtx.segments[b"__LINKEDIT"].seg.vmaddr
		)

		# Setup for symtab and dysymtab
		self._symtabCmd = self._linkeditBuilder.symtabData.command
		if self._linkeditBuilder.dysymtabData is not None:
			self._dysymtabCmd = self._linkeditBuilder.dysymtabData.command
		else:
			self._dysymtabCmd = None

		self._newSymbolData = bytearray()
		self._newIndirectSymData = bytearray()

		self._newLocalSymbolsStartIndex = 0
		self._newLocalSymbolCount = 0
		self._newExportedSymbolsStartIndex = 0
		self._newExportedSymbolCount = 0
		self._newImportedSymbolsStartIndex = 0
		self._newImportedSymbolCount = 0

		# Maps the old symbol indexes in the shared symbol table
		# 	to the new indexes in the optimized index table.
		self._oldToNewSymbolIndexes: Dict[int, int] = {}
		pass

	def run(self) -> None:
		self._addRedactedSymbol()
		self._copyLocalSymbols()
		self._copyExportedSymbols()

		# This must be run last for stub_fixer
		self._copyImportedSymbols()

		self._copyIndirectSymbolTable()

		self._statusBar.update(status="Compiling string pool")
		newStrings = self._symbolCtx.compileStrings()

		# update linkedit
		symtabData = self._linkeditBuilder.symtabData
		symtabData.symbols = self._newSymbolData
		symtabData.strings = newStrings

		if self._dysymtabCmd is not None:
			dysymtabData = self._linkeditBuilder.dysymtabData
			dysymtabData.indirectSyms = self._newIndirectSymData

			self._dysymtabCmd.ilocalsym = self._newLocalSymbolsStartIndex
			self._dysymtabCmd.nlocalsym = self._newLocalSymbolCount
			self._dysymtabCmd.iextdefsym = self._newExportedSymbolsStartIndex
			self._dysymtabCmd.nextdefsym = self._newExportedSymbolCount
			self._dysymtabCmd.iundefsym = self._newImportedSymbolsStartIndex
			self._dysymtabCmd.nundefsym = self._newImportedSymbolCount
			self._dysymtabCmd.tocoff = 0
			self._dysymtabCmd.ntoc = 0
			self._dysymtabCmd.modtaboff = 0
			self._dysymtabCmd.nmodtab = 0
			self._dysymtabCmd.extrefsymoff = 0
			self._dysymtabCmd.locreloff = 0
			self._dysymtabCmd.nlocrel = 0
			pass

		self._statusBar.update(status="Rebuilding linkedit")

		# Rebuild in same location
		linkeditOff = self._dyldCtx.convertAddr(
			self._machoCtx.segments[b"__LINKEDIT"].seg.vmaddr
		)[0]
		self._linkeditBuilder.build(linkeditOff)
		pass

	def _addRedactedSymbol(self) -> None:
		"""Adds a redacted symbol entry if needed.

			Some images have indirect symbols that point to the zeroth
		symbol entry. This is probaby a stripped symbol and may be
		unrecoverable.

		This provides a "redacted" entry for those special cases so that
		some disassemblers don't name functions incorrectly.
		"""

		self._statusBar.update(status="Search Redacted Symbols")

		indirectStart = self._dysymtabCmd.indirectsymoff
		indirectEnd = indirectStart + (self._dysymtabCmd.nindirectsyms * 4)
		for offset in range(indirectStart, indirectEnd, 4):
			symbolIndex = self._linkeditCtx.getBytes(offset, 4)
			if symbolIndex == b"\x00\x00\x00\x00":
				self._extractionCtx.hasRedactedIndirect = True

				stringIndex = self._symbolCtx.addString(b"<redacted>\x00")
				self._symbolCtx.symbolsSize += 1

				symbolEntry = nlist_64()
				symbolEntry.n_strx = stringIndex
				symbolEntry.n_type = 1
				self._newSymbolData.extend(symbolEntry)
				break

			self._statusBar.update()
			pass
		pass

	def _getLocalSymsEntryStruct(
		self,
		symbolsCache: DyldContext,
		symbolsInfo: dyld_cache_local_symbols_info
	) -> Union[
		Type[dyld_cache_local_symbols_entry],
		Type[dyld_cache_local_symbols_entry2]
	]:
		"""Get the correct struct for the local symbol entries.

		If the struct version could not be found,
		return None.
		"""

		# get the offset to the first image, and to the
		# second image. Assumes that they are next to each other.
		image1 = self._dyldCtx.convertAddr(self._dyldCtx.images[0].address)[0]
		image1 = struct.pack("<I", image1)
		image2 = self._dyldCtx.convertAddr(self._dyldCtx.images[1].address)[0]
		image2 = struct.pack("<I", image2)

		entriesOff = symbolsInfo._fileOff_ + symbolsInfo.entriesOffset
		image1Off = symbolsCache.file.find(image1, entriesOff)
		image2Off = symbolsCache.file.find(image2, entriesOff)

		structSize = image2Off - image1Off
		if structSize == dyld_cache_local_symbols_entry.SIZE:
			return dyld_cache_local_symbols_entry
		elif structSize == dyld_cache_local_symbols_entry2.SIZE:
			return dyld_cache_local_symbols_entry2
		else:
			return None

	def _copyLocalSymbols(self) -> None:
		self._statusBar.update(status="Copy Local Symbols")

		symbolsCache = self._dyldCtx.getSymbolsCache()
		localSymbolsInfo = dyld_cache_local_symbols_info(
			symbolsCache.file,
			symbolsCache.header.localSymbolsOffset
		)

		entryStruct = self._getLocalSymsEntryStruct(
			symbolsCache,
			localSymbolsInfo
		)
		if not entryStruct:
			self._logger.error("Unable to get local symbol entries structure.")
			return

		dylibOffset = (
			self._machoCtx.segments[b"__TEXT"].seg.vmaddr
			- self._dyldCtx.header.sharedRegionStart
		)

		localSymbolsEntriesInfo = None
		for i in range(localSymbolsInfo.entriesCount):
			entryOff = (i * entryStruct.SIZE)
			entryOff += localSymbolsInfo._fileOff_ + localSymbolsInfo.entriesOffset

			entry = entryStruct(symbolsCache.file, entryOff)
			if entry.dylibOffset == dylibOffset:
				localSymbolsEntriesInfo = entry
				break

		if not localSymbolsEntriesInfo:
			self._logger.warning("Unable to find local symbol entries.")
			return

		self._newLocalSymbolsStartIndex = self._symbolCtx.symbolsSize
		self._newLocalSymbolCount = 0

		# copy local symbols and their strings
		entriesStart = (
			localSymbolsInfo._fileOff_
			+ localSymbolsInfo.nlistOffset
			+ (localSymbolsEntriesInfo.nlistStartIndex * nlist_64.SIZE)
		)
		entriesEnd = (
			entriesStart
			+ (localSymbolsEntriesInfo.nlistCount * nlist_64.SIZE)
		)

		symbolStrOff = localSymbolsInfo._fileOff_ + localSymbolsInfo.stringsOffset

		for offset in range(entriesStart, entriesEnd, nlist_64.SIZE):
			symbolEnt = nlist_64(symbolsCache.file, offset)
			name = symbolsCache.readString(symbolStrOff + symbolEnt.n_strx)

			# copy data
			self._newLocalSymbolCount += 1
			self._symbolCtx.symbolsSize += 1

			symbolEnt.n_strx = self._symbolCtx.addString(name)
			self._newSymbolData.extend(symbolEnt)

			self._statusBar.update()
			pass
		pass

	def _copyExportedSymbols(self) -> None:
		self._statusBar.update("Copy Exported Symbols")

		self._newExportedSymbolsStartIndex = self._symbolCtx.symbolsSize
		self._newExportedSymbolCount = 0

		if self._dysymtabCmd is None:
			self._logger.warning("Unable to copy exported symbols.")
			return

		# Copy entries and symbols
		entriesStart = self._dysymtabCmd.iextdefsym
		entriesEnd = entriesStart + self._dysymtabCmd.nextdefsym

		symbolStrOff = self._symtabCmd.stroff

		for entryIndex in range(entriesStart, entriesEnd):
			entryOff = self._symtabCmd.symoff + (entryIndex * nlist_64.SIZE)
			entry = nlist_64(self._linkeditCtx.file, entryOff)

			nameOff = symbolStrOff + entry.n_strx
			name = self._linkeditCtx.readString(nameOff)

			# update variables and copy
			self._oldToNewSymbolIndexes[entryIndex] = self._symbolCtx.symbolsSize

			self._newExportedSymbolCount += 1
			self._symbolCtx.symbolsSize += 1

			entry.n_strx = self._symbolCtx.addString(name)
			self._newSymbolData.extend(entry)

			self._statusBar.update()
			pass
		pass

	def _copyImportedSymbols(self) -> None:
		self._statusBar.update(status="Copy Imported Symbols")

		self._newImportedSymbolsStartIndex = self._symbolCtx.symbolsSize
		self._newImportedSymbolCount = 0

		if not self._dysymtabCmd:
			self._logger.warning("Unable to copy imported symbols")
			return

		# Copy entries and symbols
		entriesStart = self._dysymtabCmd.iundefsym
		entriesEnd = entriesStart + self._dysymtabCmd.nundefsym

		symbolStrOff = self._symtabCmd.stroff

		for entryIndex in range(entriesStart, entriesEnd):
			entryOff = self._symtabCmd.symoff + (entryIndex * nlist_64.SIZE)
			entry = nlist_64(self._linkeditCtx.file, entryOff)

			nameOff = symbolStrOff + entry.n_strx
			name = self._linkeditCtx.readString(nameOff)

			# update variables and copy
			self._oldToNewSymbolIndexes[entryIndex] = self._symbolCtx.symbolsSize

			self._newImportedSymbolCount += 1
			self._symbolCtx.symbolsSize += 1

			entry.n_strx = self._symbolCtx.addString(name)
			self._newSymbolData.extend(entry)

			self._statusBar.update()
			pass
		pass

	def _copyIndirectSymbolTable(self) -> None:
		self._statusBar.update(status="Copy Indirect Symbol Table")

		if not self._dysymtabCmd:
			self._logger.warning("Unable to copy indirect symbol table")
			return

		entriesEnd = (
			self._dysymtabCmd.indirectsymoff
			+ (self._dysymtabCmd.nindirectsyms * 4)
		)

		for offset in range(self._dysymtabCmd.indirectsymoff, entriesEnd, 4):
			# Each entry is a 32bit index into the symbol table
			symbol = self._linkeditCtx.getBytes(offset, 4)
			symbolIndex = struct.unpack("<I", symbol)[0]

			if (
				symbolIndex == INDIRECT_SYMBOL_ABS
				or symbolIndex == INDIRECT_SYMBOL_LOCAL
				or symbolIndex == 0
			):
				# Do nothing to the entry
				self._newIndirectSymData.extend(symbol)
				continue

			newSymbolIndex = self._oldToNewSymbolIndexes[symbolIndex]
			self._newIndirectSymData.extend(struct.pack("<I", newSymbolIndex))

			self._statusBar.update()
			pass
		pass
	pass


def optimizeLinkedit(extractionCtx: ExtractionContext) -> None:
	"""Optimize the linkedit.

		In the dyld shared cache the linkedit is merged and shared across MachO
	files. While we can just leave it as it is, decached files will be unnecessary
	large.

		This attempts to optimize the size of the linkedit by pulling in only
	necessary data.

	Args:
		extractionCtx: The extraction context.
	"""

	extractionCtx.statusBar.update(unit="Optimize Linkedit")
	_LinkeditOptimizer(extractionCtx).run()
	pass
