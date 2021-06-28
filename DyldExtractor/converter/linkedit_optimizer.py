import struct

from DyldExtractor.extraction_context import ExtractionContext

from DyldExtractor.dyld.dyld_structs import (
	dyld_cache_local_symbols_info,
	dyld_cache_local_symbols_entry
)

from DyldExtractor.macho.macho_constants import *
from DyldExtractor.macho.macho_structs import (
	LoadCommands,
	dyld_info_command,
	dysymtab_command,
	linkedit_data_command,
	nlist_64,
	symtab_command
)


class _SymbolContext(object):

	symbolsSize: int

	def __init__(self) -> None:
		super().__init__()

		self.symbolsSize = 0

		self._stringMap: dict[bytes, int] = {}
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

		self.extractionCtx = extractionCtx
		self.machoCtx = extractionCtx.machoCtx
		self.dyldCtx = extractionCtx.dyldCtx
		self.statusBar = extractionCtx.statusBar
		self.logger = extractionCtx.logger

		self.symTabCmd: symtab_command = None
		self.dynSymTabCmd: dysymtab_command = None
		self.dyldInfo: dyld_info_command = None
		self.exportTrieCmd: linkedit_data_command = None
		self.functionStartsCmd: linkedit_data_command = None
		self.dataInCodeCmd: linkedit_data_command = None

		for lc in self.machoCtx.loadCommands:
			if lc.cmd == LoadCommands.LC_SYMTAB:
				self.symTabCmd = lc
			elif lc.cmd == LoadCommands.LC_DYSYMTAB:
				self.dynSymTabCmd = lc
			elif (
				lc.cmd == LoadCommands.LC_DYLD_INFO
				or lc.cmd == LoadCommands.LC_DYLD_INFO_ONLY
			):
				self.dyldInfo = lc
			elif lc.cmd == LoadCommands.LC_FUNCTION_STARTS:
				self.functionStartsCmd = lc
			elif lc.cmd == LoadCommands.LC_DATA_IN_CODE:
				self.dataInCodeCmd = lc
			elif lc.cmd == LoadCommands.LC_DYLD_EXPORTS_TRIE:
				self.exportTrieCmd = lc

		# Maps the old symbol indexes in the shared symbol table
		# 	to the new indexes in the optimized index table.
		self.oldToNewSymbolIndexes: dict[int, int] = {}

		self.newWeakBindingInfoOffset = 0
		self.newLazyBindingInfoOffset = 0
		self.newBindingInfoOffset = 0
		self.newExportInfoOffset = 0
		self.newExportedSymbolsStartIndex = 0
		self.newExportedSymbolCount = 0
		self.newImportedSymbolsStartIndex = 0
		self.newImportedSymbolCount = 0
		self.newLocalSymbolsStartIndex = 0
		self.newLocalSymbolCount = 0
		self.newFunctionStartsOffset = 0
		self.newDataInCodeOffset = 0
		self.newIndirectSymbolTableOffset = 0

		self.newStringPoolOffset = 0
		self.newStringPoolSize = 0

		self.newSymbolTableOffset = 0
		self.redactedSymbolCount = 0
		self.symbolCtx = None
		pass

	def copyWeakBindingInfo(self, newLinkedit: bytearray) -> None:
		self.statusBar.update(status="Copy Weak Binding Info")

		if not self.dyldInfo:
			return

		size = self.dyldInfo.weak_bind_size
		if size:
			weakBindingInfo = self.machoCtx.getBytes(self.dyldInfo.weak_bind_off, size)

			self.newWeakBindingInfoOffset = len(newLinkedit)
			newLinkedit.extend(weakBindingInfo)

		self.statusBar.update()
		pass

	def copyExportInfo(self, newLinkedit: bytearray) -> None:
		self.statusBar.update(status="Copy Export Info")

		if not self.dyldInfo and not self.exportTrieCmd:
			return

		if self.exportTrieCmd:
			exportOff = self.exportTrieCmd.dataoff
			exportSize = self.exportTrieCmd.datasize
		else:
			exportOff = self.dyldInfo.export_off
			exportSize = self.dyldInfo.export_size

		if exportSize:
			exportInfo = self.machoCtx.getBytes(exportOff, exportSize)

			self.newExportInfoOffset = len(newLinkedit)
			newLinkedit.extend(exportInfo)

		self.statusBar.update()
		pass

	def copyBindingInfo(self, newLinkedit: bytearray) -> None:
		self.statusBar.update(status="Copy Binding Info")

		if not self.dyldInfo:
			return

		size = self.dyldInfo.bind_size
		if size:
			bindingInfo = self.machoCtx.getBytes(self.dyldInfo.bind_off, size)

			self.newBindingInfoOffset = len(newLinkedit)
			newLinkedit.extend(bindingInfo)

		self.statusBar.update()
		pass

	def copyLazyBindingInfo(self, newLinkedit: bytearray) -> None:
		self.statusBar.update(status="Copy Lazy Binding Info")

		if not self.dyldInfo:
			return

		size = self.dyldInfo.lazy_bind_size
		if size:
			lazyBindingInfo = self.machoCtx.getBytes(self.dyldInfo.lazy_bind_off, size)

			self.newLazyBindingInfoOffset = len(newLinkedit)
			newLinkedit.extend(lazyBindingInfo)

		self.statusBar.update()
		pass

	def startSymbolContext(self, newLinkedit: bytearray) -> None:
		self.symbolCtx = _SymbolContext()
		self.newSymbolTableOffset = len(newLinkedit)
		pass

	def copyLocalSymbols(self, newLinkedit: bytearray) -> None:
		self.statusBar.update(status="Copy Local Symbols")

		localSymbolsInfo = dyld_cache_local_symbols_info(
			self.dyldCtx.file,
			self.dyldCtx.header.localSymbolsOffset
		)

		localSymbolsEntriesInfo = None
		for i in range(localSymbolsInfo.entriesCount):
			entryOff = (i * dyld_cache_local_symbols_entry.SIZE)
			entryOff += localSymbolsInfo._fileOff_ + localSymbolsInfo.entriesOffset

			entry = dyld_cache_local_symbols_entry(self.dyldCtx.file, entryOff)
			if entry.dylibOffset == self.machoCtx.fileOffset:
				localSymbolsEntriesInfo = entry
				break

		if not localSymbolsEntriesInfo:
			self.logger.warning("Unable to find local symbol entries.")
			return

		self.newLocalSymbolsStartIndex = self.symbolCtx.symbolsSize
		self.newLocalSymbolCount = 0

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
			symbolEnt = nlist_64(self.dyldCtx.file, offset)
			name = self.dyldCtx.readString(symbolStrOff + symbolEnt.n_strx)

			# copy data
			self.newLocalSymbolCount += 1
			self.symbolCtx.symbolsSize += 1

			symbolEnt.n_strx = self.symbolCtx.addString(name)
			newLinkedit.extend(symbolEnt)

			self.statusBar.update()
		pass

	def copyExportedSymbols(self, newLinkedit: bytearray) -> None:
		self.statusBar.update("Copy Exported Symbols")

		self.newExportedSymbolsStartIndex = self.symbolCtx.symbolsSize
		self.newExportedSymbolCount = 0

		if not self.dynSymTabCmd:
			self.logger.warning("Unable to copy exported symbols.")
			return

		# Copy entries and symbols
		entriesStart = self.dynSymTabCmd.iextdefsym
		entriesEnd = entriesStart + self.dynSymTabCmd.nextdefsym

		symbolStrOff = self.symTabCmd.stroff

		for entryIndex in range(entriesStart, entriesEnd):
			entryOff = self.symTabCmd.symoff + (entryIndex * nlist_64.SIZE)
			entry = nlist_64(self.dyldCtx.file, entryOff)

			nameOff = symbolStrOff + entry.n_strx
			name = self.dyldCtx.readString(nameOff)

			# update variables and copy
			self.oldToNewSymbolIndexes[entryIndex] = self.symbolCtx.symbolsSize

			self.newExportedSymbolCount += 1
			self.symbolCtx.symbolsSize += 1

			entry.n_strx = self.symbolCtx.addString(name)
			newLinkedit.extend(entry)

			self.statusBar.update()
		pass

	def copyImportedSymbols(self, newLinkedit: bytearray) -> None:
		self.statusBar.update(status="Copy Imported Symbols")

		self.newImportedSymbolsStartIndex = self.symbolCtx.symbolsSize
		self.newImportedSymbolCount = 0

		if not self.dynSymTabCmd:
			self.logger.warning("Unable to copy imported symbols")
			return

		# Copy entries and symbols
		entriesStart = self.dynSymTabCmd.iundefsym
		entriesEnd = entriesStart + self.dynSymTabCmd.nundefsym

		symbolStrOff = self.symTabCmd.stroff

		for entryIndex in range(entriesStart, entriesEnd):
			entryOff = self.symTabCmd.symoff + (entryIndex * nlist_64.SIZE)
			entry = nlist_64(self.dyldCtx.file, entryOff)

			nameOff = symbolStrOff + entry.n_strx
			name = self.dyldCtx.readString(nameOff)

			# update variables and copy
			self.oldToNewSymbolIndexes[entryIndex] = self.symbolCtx.symbolsSize

			self.newImportedSymbolCount += 1
			self.symbolCtx.symbolsSize += 1

			entry.n_strx = self.symbolCtx.addString(name)
			newLinkedit.extend(entry)

			self.statusBar.update()

		# make room for the indirect symbol entries that may
		# be fixed in stub_fixer
		if self.redactedSymbolCount:
			newLinkedit.extend(b"\x00" * (self.redactedSymbolCount * nlist_64.SIZE))
		pass

	def addRedactedSymbol(self, newLinkedit: bytearray) -> None:
		"""Adds a redacted symbol entry if needed.

			Some images have indirect symbols that point to the zeroth
		symbol entry. This is probaby a stripped symbol and is basically
		unrecoverable.

		This provides a "redacted" entry for those special cases so that
		some disassemblers don't name functions incorrectly.
		"""

		self.statusBar.update(status="Search Redacted Symbols")

		self.redactedSymbolCount = 0

		indirectStart = self.dynSymTabCmd.indirectsymoff
		indirectEnd = indirectStart + (self.dynSymTabCmd.nindirectsyms * 4)
		for offset in range(indirectStart, indirectEnd, 4):
			symbolIndex = self.dyldCtx.getBytes(offset, 4)
			if symbolIndex == b"\x00\x00\x00\x00":
				self.redactedSymbolCount += 1

			self.statusBar.update()
			pass

		if self.redactedSymbolCount:
			stringIndex = self.symbolCtx.addString(b"<redacted>\x00")
			self.symbolCtx.symbolsSize += 1

			symbolEntry = nlist_64()
			symbolEntry.n_strx = stringIndex
			symbolEntry.n_type = 1
			newLinkedit.extend(symbolEntry)

			self.extractionCtx.hasRedactedIndirect = True
		pass

	def copyFunctionStarts(self, newLinkedit: bytearray) -> None:
		self.statusBar.update(status="Copy Function Starts")

		if not self.functionStartsCmd:
			return

		self.newFunctionStartsOffset = len(newLinkedit)

		size = self.functionStartsCmd.datasize
		functionStarts = self.machoCtx.getBytes(self.functionStartsCmd.dataoff, size)
		newLinkedit.extend(functionStarts)

		self.statusBar.update()
		pass

	def copyDataInCode(self, newLinkedit: bytearray) -> None:
		self.statusBar.update(status="Copy Data In Code")

		if not self.dataInCodeCmd:
			return

		self.newDataInCodeOffset = len(newLinkedit)

		size = self.dataInCodeCmd.datasize
		dataInCode = self.machoCtx.getBytes(self.dataInCodeCmd.dataoff, size)
		newLinkedit.extend(dataInCode)

		self.statusBar.update()
		pass

	def copyIndirectSymbolTable(self, newLinkedit: bytearray) -> None:
		self.statusBar.update(status="Copy Indirect Symbol Table")

		self.newIndirectSymbolTableOffset = len(newLinkedit)

		if not self.dynSymTabCmd:
			return

		entriesEnd = (
			self.dynSymTabCmd.indirectsymoff
			+ (self.dynSymTabCmd.nindirectsyms * 4)
		)

		for offset in range(self.dynSymTabCmd.indirectsymoff, entriesEnd, 4):
			# Each entry is a 32bit index into the symbol table
			symbol = self.dyldCtx.getBytes(offset, 4)
			symbolIndex = struct.unpack("<I", symbol)[0]

			if (
				symbolIndex == INDIRECT_SYMBOL_ABS
				or symbolIndex == INDIRECT_SYMBOL_LOCAL
				or symbolIndex == 0
			):
				# Do nothing to the entry
				newLinkedit.extend(symbol)
				continue

			newSymbolIndex = self.oldToNewSymbolIndexes[symbolIndex]
			newLinkedit.extend(struct.pack("<I", newSymbolIndex))

			self.statusBar.update()
		pass

	def copyStringPool(self, newLinkedit: bytearray) -> None:
		self.statusBar.update(status="Copy String Pool")

		stringPool = self.symbolCtx.compileStrings()

		self.newStringPoolOffset = len(newLinkedit)
		self.newStringPoolSize = len(stringPool)
		newLinkedit.extend(stringPool)

		self.statusBar.update()
		pass

	def updateLoadCommands(
		self,
		newLinkedit: bytearray,
		newLinkeditOff: int
	) -> None:
		# update __LINKEDIT segment
		LinkeditSeg = self.machoCtx.segments[b"__LINKEDIT"].seg
		LinkeditSeg.fileoff = newLinkeditOff
		LinkeditSeg.filesize = len(newLinkedit)
		LinkeditSeg.vmsize = len(newLinkedit)

		# update Symbol table
		self.symTabCmd.symoff = newLinkeditOff + self.newSymbolTableOffset
		self.symTabCmd.nsyms = self.symbolCtx.symbolsSize

		self.symTabCmd.stroff = newLinkeditOff + self.newStringPoolOffset
		self.symTabCmd.strsize = self.newStringPoolSize

		# update Dynamic Symbol table
		if self.dynSymTabCmd:
			self.dynSymTabCmd.ilocalsym = self.newLocalSymbolsStartIndex
			self.dynSymTabCmd.nlocalsym = self.newLocalSymbolCount
			self.dynSymTabCmd.iextdefsym = self.newExportedSymbolsStartIndex
			self.dynSymTabCmd.nextdefsym = self.newExportedSymbolCount
			self.dynSymTabCmd.iundefsym = self.newImportedSymbolsStartIndex
			self.dynSymTabCmd.nundefsym = self.newImportedSymbolCount
			self.dynSymTabCmd.tocoff = 0
			self.dynSymTabCmd.ntoc = 0
			self.dynSymTabCmd.modtaboff = 0
			self.dynSymTabCmd.nmodtab = 0

			indirectsymOff = newLinkeditOff + self.newIndirectSymbolTableOffset
			self.dynSymTabCmd.indirectsymoff = indirectsymOff

			self.dynSymTabCmd.extrefsymoff = 0
			self.dynSymTabCmd.locreloff = 0
			self.dynSymTabCmd.nlocrel = 0

		# update dyld info and exports
		dyldInfo = self.dyldInfo
		if dyldInfo:
			if dyldInfo.bind_size:
				dyldInfo.bind_off = newLinkeditOff + self.newBindingInfoOffset
			if dyldInfo.weak_bind_size:
				dyldInfo.weak_bind_off = newLinkeditOff + self.newWeakBindingInfoOffset
			if dyldInfo.lazy_bind_size:
				dyldInfo.lazy_bind_off = newLinkeditOff + self.newLazyBindingInfoOffset
			if dyldInfo.export_size:
				dyldInfo.export_off = newLinkeditOff + self.newExportInfoOffset
		elif self.exportTrieCmd:
			self.exportTrieCmd.dataoff = newLinkeditOff + self.newExportInfoOffset

		# update Function starts
		functionStartsCmd = self.functionStartsCmd
		if functionStartsCmd:
			functionStartsCmd.dataoff = newLinkeditOff + self.newFunctionStartsOffset

		# update data-in-code
		if self.dataInCodeCmd:
			self.dataInCodeCmd.dataoff = newLinkeditOff + self.newDataInCodeOffset
		pass


def optimizeLinkedit(extractionCtx: ExtractionContext) -> None:
	"""Optimize the linkedit.

		In the dyld shared cache the linkedit is merged and shared across MachO
	files. While we can just leave it as it is, decached files will be unnecessary
	large.

		This attempts to optimize the size of the linkedit by pulling in only
	necessary data.

	Args:
		dyldCtx: The source dyld context.
		machoCtx: A writable MachO file to optimize.

	Returns:
		The optimized MachO file.
	"""

	extractionCtx.statusBar.update(unit="Optimize Linkedit")

	newLinkedit = bytearray()

	optimizer = _LinkeditOptimizer(extractionCtx)

	optimizer.copyWeakBindingInfo(newLinkedit)
	optimizer.copyExportInfo(newLinkedit)
	optimizer.copyBindingInfo(newLinkedit)
	optimizer.copyLazyBindingInfo(newLinkedit)

	# copy symbol entries
	optimizer.startSymbolContext(newLinkedit)
	optimizer.addRedactedSymbol(newLinkedit)
	optimizer.copyLocalSymbols(newLinkedit)
	optimizer.copyExportedSymbols(newLinkedit)
	# this needs to be run last because we might need to add
	# more space for redacted indirect symbols.
	optimizer.copyImportedSymbols(newLinkedit)

	optimizer.copyFunctionStarts(newLinkedit)
	optimizer.copyDataInCode(newLinkedit)

	# Copy Indirect Symbol Table
	optimizer.copyIndirectSymbolTable(newLinkedit)

	# make sure the new linkedit is 8-bit aligned
	if (len(newLinkedit) % 8) != 0:
		newLinkedit.extend(b"\x00" * 4)

	optimizer.copyStringPool(newLinkedit)

	# Align again
	if (len(newLinkedit) % 8) != 0:
		newLinkedit.extend(b"\x00" * 4)

	# Set the new linkedit in the same location
	machoCtx = extractionCtx.machoCtx
	newLinkeditOff = machoCtx.segments[b"__LINKEDIT"].seg.fileoff
	machoCtx.file.seek(newLinkeditOff)
	machoCtx.file.write(newLinkedit)

	optimizer.updateLoadCommands(newLinkedit, newLinkeditOff)

	extractionCtx.statusBar.update()
