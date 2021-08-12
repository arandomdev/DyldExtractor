import dataclasses
import enum
import struct
from typing import Iterator

from DyldExtractor.extraction_context import ExtractionContext
from DyldExtractor.file_context import FileContext
from DyldExtractor.converter import slide_info
from DyldExtractor import leb128

from DyldExtractor.dyld import dyld_trie

from DyldExtractor.macho.macho_context import MachOContext
from DyldExtractor.macho.macho_constants import *
from DyldExtractor.macho.macho_structs import (
	LoadCommands,
	dyld_info_command,
	dylib_command,
	dysymtab_command,
	linkedit_data_command,
	nlist_64,
	section_64,
	symtab_command
)


@dataclasses.dataclass
class _DependencyInfo(object):
	dylibPath: bytes
	imageAddress: int
	context: MachOContext


class _Symbolizer(object):

	def __init__(self, extractionCtx: ExtractionContext) -> None:
		"""Used to symbolize function in the cache.

		This will walk down the tree of dependencies and
		cache exports and function names. It will also cache
		any symbols in the MachO file.
		"""
		super().__init__()

		self._dyldCtx = extractionCtx.dyldCtx
		self._machoCtx = extractionCtx.machoCtx
		self._statusBar = extractionCtx.statusBar
		self._logger = extractionCtx.logger

		# Stores and address and the possible symbols at the address
		self._symbolCache: dict[int, list[bytes]] = {}

		# create a map of image paths and their addresses
		self._images: dict[bytes, int] = {}
		for image in self._dyldCtx.images:
			imagePath = self._dyldCtx.readString(image.pathFileOffset)
			self._images[imagePath] = image.address
			pass

		self._enumerateExports()
		self._enumerateSymbols()
		pass

	def symbolizeAddr(self, addr: int) -> list[bytes]:
		"""Get the name of a function at the address.

		Args:
			addr:  The address of the function.

		Returns:
			A set of potential name of the function.
			or None if it could not be found.
		"""
		if addr in self._symbolCache:
			return self._symbolCache[addr]
		else:
			return None

	def _enumerateExports(self) -> None:
		# process the dependencies iteratively,
		# skipping ones already processed
		depsQueue: list[_DependencyInfo] = []
		depsProcessed: list[bytes] = []

		# load commands for all dependencies
		DEP_LCS = (
			LoadCommands.LC_LOAD_DYLIB,
			LoadCommands.LC_PREBOUND_DYLIB,
			LoadCommands.LC_LOAD_WEAK_DYLIB,
			LoadCommands.LC_REEXPORT_DYLIB,
			LoadCommands.LC_LAZY_LOAD_DYLIB,
			LoadCommands.LC_LOAD_UPWARD_DYLIB
		)

		# These exports sometimes change the name of an existing
		# export symbol. We have to process them last.
		reExports: list[dyld_trie.ExportInfo] = []

		# get an initial list of dependencies
		if dylibs := self._machoCtx.getLoadCommand(DEP_LCS, multiple=True):
			for dylib in dylibs:
				if depInfo := self._getDepInfo(dylib):
					depsQueue.append(depInfo)
			pass

		while len(depsQueue):
			self._statusBar.update()

			depInfo = depsQueue.pop()

			# check if we already processed it
			if next(
				(name for name in depsProcessed if name == depInfo.dylibPath),
				None
			):
				continue

			depExports = self._readDepExports(depInfo)
			self._cacheDepExports(depInfo, depExports)
			depsProcessed.append(depInfo.dylibPath)

			# check for any ReExports dylibs
			if dylibs := depInfo.context.getLoadCommand(DEP_LCS, multiple=True):
				for dylib in dylibs:
					if dylib.cmd == LoadCommands.LC_REEXPORT_DYLIB:
						if depInfo := self._getDepInfo(dylib):
							depsQueue.append(depInfo)
				pass

			# check for any ReExport exports
			reExportOrdinals = set()
			for export in depExports:
				if export.flags & EXPORT_SYMBOL_FLAGS_REEXPORT:
					reExportOrdinals.add(export.other)
					reExports.append(export)
				pass

			for ordinal in reExportOrdinals:
				dylib = dylibs[ordinal - 1]
				if depInfo := self._getDepInfo(dylib):
					depsQueue.append(depInfo)
				pass
			pass

		# process and add ReExport exports
		for reExport in reExports:
			if reExport.importName == b"\x00":
				continue

			found = False

			name = reExport.importName
			for export in self._symbolCache.values():
				if name in export:
					# ReExport names should get priority
					export.insert(0, bytes(reExport.name))
					found = True
					break

			if not found:
				self._logger.warning(f"No root export for ReExport with symbol {name}")
		pass

	def _getDepInfo(self, dylib: dylib_command) -> _DependencyInfo:
		"""Given a dylib command, get dependency info.
		"""

		dylibPathOff = dylib._fileOff_ + dylib.dylib.name.offset
		dylibPath = self._dyldCtx.readString(dylibPathOff)
		if dylibPath not in self._images:
			self._logger.warning(f"Unable to find dependency: {dylibPath}")
			return None

		imageAddr = self._images[dylibPath]
		imageOff = self._dyldCtx.convertAddr(imageAddr)
		context = MachOContext(self._dyldCtx.file, imageOff)
		return _DependencyInfo(dylibPath, imageAddr, context)

	def _readDepExports(
		self,
		depInfo: _DependencyInfo
	) -> list[dyld_trie.ExportInfo]:
		exportOff = None
		exportSize = None

		dyldInfo: dyld_info_command = depInfo.context.getLoadCommand(
			(LoadCommands.LC_DYLD_INFO, LoadCommands.LC_DYLD_INFO_ONLY)
		)
		exportTrie: linkedit_data_command = depInfo.context.getLoadCommand(
			(LoadCommands.LC_DYLD_EXPORTS_TRIE,)
		)

		if dyldInfo and dyldInfo.export_size:
			exportOff = dyldInfo.export_off
			exportSize = dyldInfo.export_size
		elif exportTrie and exportTrie.datasize:
			exportOff = exportTrie.dataoff
			exportSize = exportTrie.datasize

		if exportOff is None:
			# Some images like UIKit don't have exports
			return []

		try:
			depExports = dyld_trie.ReadExports(
				depInfo.context.file,
				exportOff,
				exportSize,
			)
			return depExports
		except dyld_trie.ExportReaderError as e:
			self._logger.warning(f"Unable to read exports of {depInfo.dylibPath}, reason: {e}")  # noqa
			return []

	def _cacheDepExports(
		self,
		depInfo: _DependencyInfo,
		exports: list[dyld_trie.ExportInfo]
	) -> None:
		for export in exports:
			if not export.address:
				continue

			exportAddr = depInfo.imageAddress + export.address
			if exportAddr in self._symbolCache:
				self._symbolCache[exportAddr].append(bytes(export.name))
			else:
				self._symbolCache[exportAddr] = [bytes(export.name)]

			if export.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER:
				# The address points to the stub, while "other" points
				# to the function itself. Add the function as well.

				functionAddr = depInfo.imageAddress + export.other

				if functionAddr in self._symbolCache:
					self._symbolCache[functionAddr].append(bytes(export.name))
				else:
					self._symbolCache[functionAddr] = [bytes(export.name)]
		pass

	def _enumerateSymbols(self) -> None:
		"""Cache potential symbols in the symbol table.
		"""

		symtab: symtab_command = self._machoCtx.getLoadCommand(
			(LoadCommands.LC_SYMTAB,)
		)
		if not symtab:
			self._logger.warning("Unable to find LC_SYMTAB.")
			return

		dysymtab: dysymtab_command = self._machoCtx.getLoadCommand(
			(LoadCommands.LC_DYSYMTAB,)
		)
		if not dysymtab:
			self._logger.warning("Unable to find LC_DYSYMTAB.")

		for i in range(symtab.nsyms):
			self._statusBar.update()

			# Get the symbol and its address
			entryOff = symtab.symoff + (i * nlist_64.SIZE)
			symbolEntry = nlist_64(self._machoCtx.file, entryOff)

			symbolAddr = symbolEntry.n_value
			symbol = self._machoCtx.readString(symtab.stroff + symbolEntry.n_strx)

			if symbolAddr == 0:
				continue
			if not self._machoCtx.containsAddr(symbolAddr):
				self._logger.warning(f"Invalid address: {symbolAddr}, for symbol entry: {symbol}.")  # noqa
				continue

			# save it to the cache
			if symbolAddr in self._symbolCache:
				self._symbolCache[symbolAddr].append(bytes(symbol))
			else:
				self._symbolCache[symbolAddr] = [bytes(symbol)]
			pass
		pass
	pass


class _StubFormat(enum.Enum):
	# Non optimized stub with a symbol pointer
	# and a stub helper.
	StubNormal = 1

	# Optimized stub with a symbol pointer
	# and a stub helper.
	StubOptimized = 2

	# Non optimized auth stub with a symbol pointer.
	AuthStubNormal = 3

	# Optimized auth stub with a branch to a function.
	AuthStubOptimized = 4

	# Non optimized auth stub with a symbol pointer
	# and a resolver.
	AuthStubResolver = 5

	# A special stub helper with a branch to a function.
	Resolver = 6
	pass


class Arm64Utilities(object):

	def __init__(self, extractionCtx: ExtractionContext) -> None:
		super().__init__()

		self._dyldCtx = extractionCtx.dyldCtx
		self._slider = slide_info.PointerSlider(extractionCtx)

		def getResolverTarget(address):
			if resolverData := self.getResolverData(address):
				# Don't need the size of the resolver
				return resolverData[0]
			else:
				return None

		self._stubResolvers = (
			(self._getStubNormalTarget, _StubFormat.StubNormal),
			(self._getStubOptimizedTarget, _StubFormat.StubOptimized),
			(self._getAuthStubNormalTarget, _StubFormat.AuthStubNormal),
			(self._getAuthStubOptimizedTarget, _StubFormat.AuthStubOptimized),
			(self._getAuthStubResolverTarget, _StubFormat.AuthStubResolver),
			(getResolverTarget, _StubFormat.Resolver)
		)

		# A cache of resolved stub chains
		self._resolveCache: dict[int, int] = {}
		pass

	def generateStubNormal(self, stubAddress: int, ldrAddress: int) -> bytes:
		"""Create a normal stub.

		Args:
			stubAddress: The address of the stub to generate.
			ldrAddress: The address of the pointer targeted by the ldr instruction.

		Returns:
			The bytes of the generated stub.
		"""

		# ADRP X16, lp@page
		adrpDelta = (ldrAddress & -4096) - (stubAddress & -4096)
		immhi = (adrpDelta >> 9) & (0x00FFFFE0)
		immlo = (adrpDelta << 17) & (0x60000000)
		newAdrp = (0x90000010) | immlo | immhi

		# LDR X16, [X16, lp@pageoff]
		ldrOffset = ldrAddress - (ldrAddress & -4096)
		imm12 = (ldrOffset << 7) & 0x3FFC00
		newLdr = 0xF9400210 | imm12

		# BR X16
		newBr = 0xD61F0200

		return struct.pack("<III", newAdrp, newLdr, newBr)

	def generateAuthStubNormal(self, stubAddress: int, ldrAddress: int) -> bytes:
		"""Create a normal auth stub.

		Args:
			stubAddress: The address of the stub to generate.
			ldrAddress: The address of the pointer targeted by the ldr instruction.

		Returns:
			The bytes of the generated stub.
		"""

		"""
		91 59 11 90  adrp 	x17,0x1e27e5000
		31 22 0d 91  add 	x17,x17,#0x348
		30 02 40 f9  ldr 	x16,[x17]=>->__auth_stubs::_CCRandomCopyBytes = 1bfcb5d50
		11 0a 1f d7  braa 	x16=>__auth_stubs::_CCRandomCopyBytes,x17
		"""

		# ADRP X17, sp@page
		adrpDelta = (ldrAddress & -4096) - (stubAddress & -4096)
		immhi = (adrpDelta >> 9) & (0x00FFFFE0)
		immlo = (adrpDelta << 17) & (0x60000000)
		newAdrp = (0x90000011) | immlo | immhi

		# ADD X17, [X17, sp@pageoff]
		addOffset = ldrAddress - (ldrAddress & -4096)
		imm12 = (addOffset << 10) & 0x3FFC00
		newAdd = 0x91000231 | imm12

		# LDR X16, [X17, 0]
		newLdr = 0xF9400230

		# BRAA X16
		newBraa = 0xD71F0A11

		return struct.pack("<IIII", newAdrp, newAdd, newLdr, newBraa)

	def resolveStubChain(self, address: int) -> int:
		"""Follow a stub to its target function.

		Args:
			address: The address of the stub.

		Returns:
			The final target of the stub chain.
		"""

		if address in self._resolveCache:
			return self._resolveCache[address]

		target = address
		while True:
			if stubData := self.resolveStub(target):
				target = stubData[0]
			else:
				break

		self._resolveCache[address] = target
		return target

	def resolveStub(self, address: int) -> tuple[int, _StubFormat]:
		"""Get the stub and its format.

		Args:
			address: The address of the stub.

		Returns:
			A tuple containing the target of the branch
			and its format, or None if it could not be
			determined.
		"""

		for resolver, stubFormat in self._stubResolvers:
			if (result := resolver(address)) is not None:
				return (result, stubFormat)
			pass
		return None

	def getStubHelperData(self, address: int) -> int:
		"""Get the bind data of a stub helper.

		Args:
			address: The address of the stub helper.

		Returns:
			The bind data associated with a stub helper.
			If unable to get the bind data, return None.
		"""

		if not (helperOff := self._dyldCtx.convertAddr(address)):
			return None

		ldr, b, data = self._dyldCtx.readFormat(helperOff, "<III")

		# verify
		if (
			(ldr & 0xBF000000) != 0x18000000
			or (b & 0xFC000000) != 0x14000000
		):
			return None

		return data

	def getResolverData(self, address: int) -> tuple[int, int]:
		"""Get the data of a resolver.

		This is a stub helper that branches to a function
		that should be within the same MachO file.

		Args:
			address: The address of the resolver.

		Returns:
			A tuple containing the target of the resolver
			and its size. Or None if it could not be determined.
		"""

		"""
		fd 7b bf a9  stp 	x29,x30,[sp, #local_10]!
		fd 03 00 91  mov 	x29,sp
		e1 03 bf a9  stp 	x1,x0,[sp, #local_20]!
		e3 0b bf a9  stp 	x3,x2,[sp, #local_30]!
		e5 13 bf a9  stp 	x5,x4,[sp, #local_40]!
		e7 1b bf a9  stp 	x7,x6,[sp, #local_50]!
		e1 03 bf 6d  stp 	d1,d0,[sp, #local_60]!
		e3 0b bf 6d  stp 	d3,d2,[sp, #local_70]!
		e5 13 bf 6d  stp 	d5,d4,[sp, #local_80]!
		e7 1b bf 6d  stp 	d7,d6,[sp, #local_90]!
		5f d4 fe 97  bl 	_vDSP_vadd
		70 e6 26 90  adrp 	x16,0x1e38ba000
		10 02 0f 91  add 	x16,x16,#0x3c0
		00 02 00 f9  str 	x0,[x16]
		f0 03 00 aa  mov 	x16,x0
		e7 1b c1 6c  ldp 	d7,d6,[sp], #0x10
		e5 13 c1 6c  ldp 	d5,d4,[sp], #0x10
		e3 0b c1 6c  ldp 	d3,d2,[sp], #0x10
		e1 03 c1 6c  ldp 	d1,d0,[sp], #0x10
		e7 1b c1 a8  ldp 	x7,x6,[sp], #0x10
		e5 13 c1 a8  ldp 	x5,x4,[sp], #0x10
		e3 0b c1 a8  ldp 	x3,x2,[sp], #0x10
		e1 03 c1 a8  ldp 	x1,x0,[sp], #0x10
		fd 7b c1 a8  ldp 	x29=>local_10,x30,[sp], #0x10
		1f 0a 1f d6  braaz 	x16

		Because the format is not the same across iOS versions,
		the following conditions are used to verify it.
		* Starts with stp and mov
		* A branch within an arbitrary threshold
		* bl is in the middle
		* adrp is directly after bl
		* ldp is directly before the branch
		"""

		SEARCH_LIMIT = 0xC8

		if not (stubOff := self._dyldCtx.convertAddr(address)):
			return None

		# test stp and mov
		stp, mov = self._dyldCtx.readFormat(stubOff, "<II")
		if (
			(stp & 0x7FC00000) != 0x29800000
			or (mov & 0x7F3FFC00) != 0x11000000
		):
			return None

		# Find the branch instruction
		dataSource = self._dyldCtx.file
		branchInstrOff = None
		for instrOff in range(stubOff, stubOff + SEARCH_LIMIT, 4):
			# (instr & 0xFE9FF000) == 0xD61F0000
			if (
				dataSource[instrOff + 1] & 0xF0 == 0x00
				and dataSource[instrOff + 2] & 0x9F == 0x1F
				and dataSource[instrOff + 3] & 0xFE == 0xD6
			):
				branchInstrOff = instrOff
				break
			pass

		if branchInstrOff is None:
			return None

		# find the bl instruction
		blInstrOff = None
		for instrOff in range(stubOff, branchInstrOff, 4):
			# (instruction & 0xFC000000) == 0x94000000
			if (dataSource[instrOff + 3] & 0xFC) == 0x94:
				blInstrOff = instrOff
				break
			pass

		if blInstrOff is None:
			return None

		# Test if there is a stp before the bl and a ldp before the braaz
		adrp = self._dyldCtx.readFormat(blInstrOff + 4, "<I")[0]
		ldp = self._dyldCtx.readFormat(branchInstrOff - 4, "<I")[0]
		if (
			(adrp & 0x9F00001F) != 0x90000010
			or (ldp & 0x7FC00000) != 0x28C00000
		):
			return None

		# Hopefully it's a resolver...
		imm = (self._dyldCtx.readFormat(blInstrOff, "<I")[0] & 0x3FFFFFF) << 2
		imm = self.signExtend(imm, 28)
		blResult = address + (blInstrOff - stubOff) + imm

		resolverSize = branchInstrOff - stubOff + 4
		return (blResult, resolverSize)

	def getStubLdrAddr(self, address: int) -> int:
		"""Get the ldr address of a normal stub.

		Args:
			address: The address of the stub.

		Returns:
			The address of the ldr, or None if it can't
			be determined.
		"""

		if (ldrAddr := self._getStubNormalLdrAddr(address)) is not None:
			return ldrAddr
		elif (ldrAddr := self._getAuthStubNormalLdrAddr(address)) is not None:
			return ldrAddr
		else:
			return None

	@staticmethod
	def signExtend(value: int, size: int) -> int:
		if value & (1 << (size - 1)):
			return value - (1 << size)

		return value

	def _getStubNormalLdrAddr(self, address: int) -> int:
		"""Get the ldr address of a normal stub.

		Args:
			address: The address of the stub.

		Returns:
			The address of the ldr, or None if it can't
			be determined.
		"""

		if not (stubOff := self._dyldCtx.convertAddr(address)):
			return None

		adrp, ldr, br = self._dyldCtx.readFormat(stubOff, "<III")

		# verify
		if (
			(adrp & 0x9F00001F) != 0x90000010
			or (ldr & 0xFFC003FF) != 0xF9400210
			or br != 0xD61F0200
		):
			return None

		# adrp
		immlo = (adrp & 0x60000000) >> 29
		immhi = (adrp & 0xFFFFE0) >> 3
		imm = (immhi | immlo) << 12
		imm = self.signExtend(imm, 33)

		adrpResult = (address & ~0xFFF) + imm

		# ldr
		imm12 = (ldr & 0x3FFC00) >> 7
		return adrpResult + imm12

	def _getAuthStubNormalLdrAddr(self, address: int) -> int:
		"""Get the Ldr address of a normal auth stub.

		Args:
			address: The address of the stub.

		Returns:
			The Ldr address of the stub or None if it could
			not be determined.
		"""

		if not (stubOff := self._dyldCtx.convertAddr(address)):
			return None

		adrp, add, ldr, braa = self._dyldCtx.readFormat(
			stubOff,
			"<IIII"
		)

		# verify
		if (
			(adrp & 0x9F000000) != 0x90000000
			or (add & 0xFFC00000) != 0x91000000
			or (ldr & 0xFFC00000) != 0xF9400000
			or (braa & 0xFEFFF800) != 0xD61F0800
		):
			return None

		# adrp
		immhi = (adrp & 0xFFFFE0) >> 3
		immlo = (adrp & 0x60000000) >> 29
		imm = (immhi | immlo) << 12
		imm = self.signExtend(imm, 33)
		adrpResult = (address & ~0xFFF) + imm

		# add
		imm = (add & 0x3FFC00) >> 10
		addResult = adrpResult + imm

		# ldr
		imm = (ldr & 0x3FFC00) >> 7
		return addResult + imm

	def _getStubNormalTarget(self, address: int) -> int:
		"""
		ADRP x16, page
		LDR x16, [x16, pageoff]
		BR x16
		"""

		if not (stubOff := self._dyldCtx.convertAddr(address)):
			return None

		adrp, ldr, br = self._dyldCtx.readFormat(stubOff, "<III")

		# verify
		if (
			(adrp & 0x9F00001F) != 0x90000010
			or (ldr & 0xFFC003FF) != 0xF9400210
			or br != 0xD61F0200
		):
			return None

		# adrp
		immlo = (adrp & 0x60000000) >> 29
		immhi = (adrp & 0xFFFFE0) >> 3
		imm = (immhi | immlo) << 12
		imm = self.signExtend(imm, 33)
		adrpResult = (address & ~0xFFF) + imm

		# ldr
		offset = (ldr & 0x3FFC00) >> 7
		ldrTarget = adrpResult + offset
		return self._slider.slideAddress(ldrTarget)

	def _getStubOptimizedTarget(self, address: int) -> int:
		"""
		ADRP x16, page
		ADD x16, x16, offset
		BR x16
		"""

		if not (stubOff := self._dyldCtx.convertAddr(address)):
			return None

		adrp, add, br = self._dyldCtx.readFormat(stubOff, "<III")

		# verify
		if (
			(adrp & 0x9F00001F) != 0x90000010
			or (add & 0xFFC003FF) != 0x91000210
			or br != 0xD61F0200
		):
			return None

		# adrp
		immlo = (adrp & 0x60000000) >> 29
		immhi = (adrp & 0xFFFFE0) >> 3
		imm = (immhi | immlo) << 12
		imm = self.signExtend(imm, 33)
		adrpResult = (address & ~0xFFF) + imm

		# add
		imm12 = (add & 0x3FFC00) >> 10
		return adrpResult + imm12

	def _getAuthStubNormalTarget(self, address: int) -> int:
		"""
		91 59 11 90  adrp  	x17,0x1e27e5000
		31 22 0d 91  add  	x17,x17,#0x348
		30 02 40 f9  ldr  	x16,[x17]=>->__auth_stubs::_CCRandomCopyBytes
		11 0a 1f d7  braa  	x16=>__auth_stubs::_CCRandomCopyBytes,x17
		"""

		if not (stubOff := self._dyldCtx.convertAddr(address)):
			return None

		adrp, add, ldr, braa = self._dyldCtx.readFormat(stubOff, "<IIII")

		# verify
		if (
			(adrp & 0x9F000000) != 0x90000000
			or (add & 0xFFC00000) != 0x91000000
			or (ldr & 0xFFC00000) != 0xF9400000
			or (braa & 0xFEFFF800) != 0xD61F0800
		):
			return None

		# adrp
		immhi = (adrp & 0xFFFFE0) >> 3
		immlo = (adrp & 0x60000000) >> 29
		imm = (immhi | immlo) << 12
		imm = self.signExtend(imm, 33)
		adrpResult = (address & ~0xFFF) + imm

		# add
		imm = (add & 0x3FFC00) >> 10
		addResult = adrpResult + imm

		# ldr
		imm = (ldr & 0x3FFC00) >> 7
		ldrTarget = addResult + imm
		return self._slider.slideAddress(ldrTarget)
		pass

	def _getAuthStubOptimizedTarget(self, address: int) -> int:
		"""
		1bfcb5d20 30 47 e2 90  adrp  	x16,0x184599000
		1bfcb5d24 10 62 30 91  add  	x16,x16,#0xc18
		1bfcb5d28 00 02 1f d6  br  		x16=>LAB_184599c18
		1bfcb5d2c 20 00 20 d4  trap
		"""

		if not (stubOff := self._dyldCtx.convertAddr(address)):
			return None

		adrp, add, br, trap = self._dyldCtx.readFormat(stubOff, "<IIII")

		# verify
		if (
			(adrp & 0x9F000000) != 0x90000000
			or (add & 0xFFC00000) != 0x91000000
			or br != 0xD61F0200
			or trap != 0xD4200020
		):
			return None

		# adrp
		immhi = (adrp & 0xFFFFE0) >> 3
		immlo = (adrp & 0x60000000) >> 29
		imm = (immhi | immlo) << 12
		imm = self.signExtend(imm, 33)
		adrpResult = (address & ~0xFFF) + imm

		# add
		imm = (add & 0x3FFC00) >> 10
		return adrpResult + imm

	def _getAuthStubResolverTarget(self, address: int) -> int:
		"""
		70 e6 26 b0  adrp 	x16,0x1e38ba000
		10 e6 41 f9  ldr 	x16,[x16, #0x3c8]
		1f 0a 1f d6  braaz 	x16=>FUN_195bee070
		"""

		if not (stubOff := self._dyldCtx.convertAddr(address)):
			return None

		adrp, ldr, braaz = self._dyldCtx.readFormat(stubOff, "<III")

		# verify
		if (
			(adrp & 0x9F000000) != 0x90000000
			or (ldr & 0xFFC00000) != 0xF9400000
			or (braaz & 0xFEFFF800) != 0xD61F0800
		):
			return None

		# adrp
		immhi = (adrp & 0xFFFFE0) >> 3
		immlo = (adrp & 0x60000000) >> 29
		imm = (immhi | immlo) << 12
		imm = self.signExtend(imm, 33)
		adrpResult = (address & ~0xFFF) + imm

		# ldr
		imm = (ldr & 0x3FFC00) >> 7
		ldrTarget = adrpResult + imm
		return self._slider.slideAddress(ldrTarget)
	pass


@dataclasses.dataclass
class _BindRecord(object):
	ordinal: int = None
	flags: int = None
	symbol: bytes = None
	symbolType: int = None
	addend: int = None
	segment: int = None
	offset: int = None
	pass


def _bindReader(
	fileCtx: FileContext,
	bindOff: int,
	bindSize: int
) -> Iterator[_BindRecord]:
	"""Read all the bind records

	Args:
		fileCtx: The source file to read from.
		bindOff: The offset in the fileCtx to read from.
		bindSize: The total size of the bind data.

	Returns:
		A list of bind records.

	Raises:
		KeyError: If the reader encounters an unknown bind opcode.
	"""

	file = fileCtx.file

	currentRecord = _BindRecord()
	bindDataEnd = bindOff + bindSize
	while bindOff < bindDataEnd:
		bindOpcodeImm = file[bindOff]
		opcode = bindOpcodeImm & BIND_OPCODE_MASK
		imm = bindOpcodeImm & BIND_IMMEDIATE_MASK

		bindOff += 1

		if opcode == BIND_OPCODE_DONE:
			# Only resets the record apparently
			currentRecord = _BindRecord()
			pass

		elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
			currentRecord.ordinal = imm
			pass

		elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
			currentRecord.ordinal, bindOff = leb128.decodeUleb128(file, bindOff)
			pass

		elif opcode == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
			if imm == 0:
				currentRecord.ordinal = BIND_SPECIAL_DYLIB_SELF
			else:
				if imm == 1:
					currentRecord.ordinal = BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE
				elif imm == 2:
					currentRecord.ordinal = BIND_SPECIAL_DYLIB_FLAT_LOOKUP
				elif imm == 3:
					currentRecord.ordinal = BIND_SPECIAL_DYLIB_WEAK_LOOKUP
				else:
					raise KeyError(f"Unknown special ordinal: {imm}")
			pass

		elif opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
			currentRecord.flags = imm
			currentRecord.symbol = fileCtx.readString(bindOff)
			bindOff += len(currentRecord.symbol)
			pass

		elif opcode == BIND_OPCODE_SET_TYPE_IMM:
			currentRecord.symbolType = imm
			pass

		elif opcode == BIND_OPCODE_SET_ADDEND_SLEB:
			currentRecord.addend, bindOff = leb128.decodeSleb128(file, bindOff)
			pass

		elif opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
			currentRecord.segment = imm
			currentRecord.offset, bindOff = leb128.decodeUleb128(file, bindOff)
			pass

		elif opcode == BIND_OPCODE_ADD_ADDR_ULEB:
			add, bindOff = leb128.decodeUleb128(file, bindOff)
			add = Arm64Utilities.signExtend(add, 64)
			currentRecord.offset += add
			pass

		elif opcode == BIND_OPCODE_DO_BIND:
			yield dataclasses.replace(currentRecord)
			currentRecord.offset += 8
			pass

		elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
			yield dataclasses.replace(currentRecord)

			add, bindOff = leb128.decodeUleb128(file, bindOff)
			add = Arm64Utilities.signExtend(add, 64)
			currentRecord.offset += add + 8
			pass

		elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
			yield dataclasses.replace(currentRecord)
			currentRecord.offset += (imm * 8) + 8
			pass

		elif opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
			count, bindOff = leb128.decodeUleb128(file, bindOff)
			skip, bindOff = leb128.decodeUleb128(file, bindOff)

			for _ in range(count):
				yield dataclasses.replace(currentRecord)
				currentRecord.offset += skip + 8
			pass

		else:
			raise KeyError(f"Unknown bind opcode: {opcode}")
		pass
	pass


class _StubFixerError(Exception):
	pass


class _StubFixer(object):

	def __init__(self, extractionCtx: ExtractionContext) -> None:
		super().__init__()

		self._extractionCtx = extractionCtx
		self._dyldCtx = extractionCtx.dyldCtx
		self._machoCtx = extractionCtx.machoCtx
		self._statusBar = extractionCtx.statusBar
		self._logger = extractionCtx.logger
		pass

	def run(self):
		self._statusBar.update(status="Caching Symbols")
		self._symbolizer = _Symbolizer(self._extractionCtx)
		self._arm64Utils = Arm64Utilities(self._extractionCtx)
		self._slider = slide_info.PointerSlider(self._extractionCtx)

		self._symtab: symtab_command = self._machoCtx.getLoadCommand(
			(LoadCommands.LC_SYMTAB,)
		)
		if not self._symtab:
			raise _StubFixerError("Unable to get symtab_command.")

		self._dysymtab: dysymtab_command = self._machoCtx.getLoadCommand(
			(LoadCommands.LC_DYSYMTAB,)
		)
		if not self._dysymtab:
			raise _StubFixerError("Unable to get dysymtab_command.")

		symbolPtrs = self._enumerateSymbolPointers()
		self._fixStubHelpers()

		stubMap = self._fixStubs(symbolPtrs)
		self._fixCallsites(stubMap)
		self._fixIndirectSymbols(symbolPtrs, stubMap)
		pass

	def _enumerateSymbolPointers(self) -> dict[bytes, tuple[int]]:
		"""Generate a mapping between a pointer's symbol and its address.
		"""

		# read all the bind records as they're a source of symbolic info
		bindRecords: dict[int, _BindRecord] = {}
		dyldInfo: dyld_info_command = self._machoCtx.getLoadCommand(
			(LoadCommands.LC_DYLD_INFO, LoadCommands.LC_DYLD_INFO_ONLY)
		)
		if dyldInfo:
			records: list[_BindRecord] = []
			try:
				if dyldInfo.weak_bind_size:
					# usually contains records for c++ symbols like "new"
					records.extend(
						_bindReader(
							self._machoCtx,
							dyldInfo.weak_bind_off,
							dyldInfo.weak_bind_size
						)
					)
					pass

				if dyldInfo.lazy_bind_off:
					records.extend(
						_bindReader(
							self._machoCtx,
							dyldInfo.lazy_bind_off,
							dyldInfo.lazy_bind_size
						)
					)
					pass

				for record in records:
					# check if we have the info needed
					if (
						record.symbol is None
						or record.segment is None
						or record.offset is None
					):
						self._logger.warning(f"Incomplete lazy bind record: {record}")
						continue

					bindAddr = self._machoCtx.segmentsI[record.segment].seg.vmaddr
					bindAddr += record.offset
					bindRecords[bindAddr] = record
					pass
			except KeyError as e:
				self._logger.error(f"Unable to read bind records, reasons: {e}")
			pass

		# enumerate all symbol pointers
		symbolPtrs: dict[bytes, list[int]] = {}

		def _addToMap(ptrSymbol: bytes, ptrAddr: int, section: section_64):
			if ptrSymbol in symbolPtrs:
				# give priority to ptrs in the __auth_got section
				if section.sectname == b"__auth_got":
					symbolPtrs[ptrSymbol].insert(0, ptrAddr)
				else:
					symbolPtrs[ptrSymbol].append(ptrAddr)
			else:
				symbolPtrs[ptrSymbol] = [ptrAddr]
			pass

		for segment in self._machoCtx.segmentsI:
			for sect in segment.sectsI:
				sectType = sect.flags & SECTION_TYPE
				if (
					sectType == S_NON_LAZY_SYMBOL_POINTERS
					or sectType == S_LAZY_SYMBOL_POINTERS
				):
					for i in range(int(sect.size / 8)):
						self._statusBar.update(status="Caching Symbol Pointers")

						ptrAddr = sect.addr + (i * 8)

						# Try to symbolize through bind records
						if ptrAddr in bindRecords:
							_addToMap(bindRecords[ptrAddr].symbol, ptrAddr, sect)
							continue

						# Try to symbolize though indirect symbol entries
						symbolIndex = self._machoCtx.readFormat(
							self._dysymtab.indirectsymoff + ((sect.reserved1 + i) * 4),
							"<I"
						)[0]
						if (
							symbolIndex != 0
							and symbolIndex != INDIRECT_SYMBOL_ABS
							and symbolIndex != INDIRECT_SYMBOL_LOCAL
							and symbolIndex != (INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL)
						):
							symbolEntry = nlist_64(
								self._machoCtx.file,
								self._symtab.symoff + (symbolIndex * nlist_64.SIZE)
							)
							symbol = self._machoCtx.readString(
								self._symtab.stroff + symbolEntry.n_strx
							)

							_addToMap(symbol, ptrAddr, sect)
							continue

						# Try to symbolize though the pointers target
						ptrTarget = self._slider.slideAddress(ptrAddr)
						ptrFunc = self._arm64Utils.resolveStubChain(ptrTarget)
						if symbols := self._symbolizer.symbolizeAddr(ptrFunc):
							for sym in symbols:
								_addToMap(sym, ptrAddr, sect)
							continue

						# Skip special cases like __csbitmaps in CoreFoundation
						if self._machoCtx.containsAddr(ptrTarget):
							continue

						self._logger.warning(f"Unable to symbolize pointer at {hex(ptrAddr)}, with indirect entry index {hex(sect.reserved1 + i)}, with target function {hex(ptrFunc)}")  # noqa
						pass
					pass
				pass
			pass

		return symbolPtrs

	def _fixStubHelpers(self) -> None:
		"""Relink symbol pointers to stub helpers.
		"""

		STUB_BINDER_SIZE = 0x18
		REG_HELPER_SIZE = 0xC

		try:
			helperSect = self._machoCtx.segments[b"__TEXT"].sects[b"__stub_helper"]
		except KeyError:
			return

		dyldInfo: dyld_info_command = self._machoCtx.getLoadCommand(
			(LoadCommands.LC_DYLD_INFO, LoadCommands.LC_DYLD_INFO_ONLY)
		)
		if not dyldInfo:
			return

		# the stub helper section has the stub binder in
		# beginning, skip it.
		helperAddr = helperSect.addr + STUB_BINDER_SIZE
		helperEnd = helperSect.addr + helperSect.size

		while helperAddr < helperEnd:
			self._statusBar.update(status="Fixing Lazy symbol Pointers")

			if (bindOff := self._arm64Utils.getStubHelperData(helperAddr)) is not None:
				record = next(
					_bindReader(
						self._machoCtx,
						dyldInfo.lazy_bind_off + bindOff,
						dyldInfo.lazy_bind_size,
					),
					None
				)

				if (
					record is None
					or record.symbol is None
					or record.segment is None
					or record.offset is None
				):
					self._logger.warning(f"Bind record for stub helper is incomplete: {record}")  # noqa
					helperAddr += REG_HELPER_SIZE
					continue

				# repoint the bind pointer to the stub helper
				bindPtrOff = self._machoCtx.segmentsI[record.segment].seg.fileoff
				bindPtrOff += record.offset

				newBindPtr = struct.pack("<Q", helperAddr)
				self._machoCtx.writeBytes(bindPtrOff, newBindPtr)
				helperAddr += REG_HELPER_SIZE
				continue

			# it may be a resolver
			if resolverInfo := self._arm64Utils.getResolverData(helperAddr):
				# it shouldn't need fixing but check it just in case.
				if not self._machoCtx.containsAddr(resolverInfo[0]):
					self._logger.warning(f"Unable to fix resolver at {hex(helperAddr)}")

				helperAddr += resolverInfo[1]  # add by resolver size
				continue

			self._logger.warning(f"Unknown stub helper format at {hex(helperAddr)}")
			helperAddr += REG_HELPER_SIZE
			pass
		pass

	def _fixStubs(
		self,
		symbolPtrs: dict[bytes, tuple[int]]
	) -> dict[bytes, tuple[int]]:
		"""Relink stubs to their symbol pointers
		"""

		stubMap: dict[bytes, list[int]] = {}

		def _addToMap(stubName: bytes, stubAddr: int):
			if stubName in stubMap:
				stubMap[stubName].append(stubAddr)
			else:
				stubMap[stubName] = [stubAddr]
			pass

		for segment in self._machoCtx.segmentsI:
			for sect in segment.sectsI:
				if sect.flags & SECTION_TYPE == S_SYMBOL_STUBS:
					for i in range(int(sect.size / sect.reserved2)):
						self._statusBar.update(status="Fixing Stubs")

						stubAddr = sect.addr + (i * sect.reserved2)

						# First symbolize the stub
						stubNames = None

						# Try to symbolize though indirect symbol entries
						symbolIndex = self._machoCtx.readFormat(
							self._dysymtab.indirectsymoff + ((sect.reserved1 + i) * 4),
							"<I"
						)[0]

						if (
							symbolIndex != 0
							and symbolIndex != INDIRECT_SYMBOL_ABS
							and symbolIndex != INDIRECT_SYMBOL_LOCAL
							and symbolIndex != (INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL)
						):
							symbolEntry = nlist_64(
								self._machoCtx.file,
								self._symtab.symoff + (symbolIndex * nlist_64.SIZE)
							)
							stubNames = [
								self._machoCtx.readString(self._symtab.stroff + symbolEntry.n_strx)
							]
							pass

						# If the stub isn't optimized,
						# try to symbolize it though its pointer
						if not stubNames:
							if (ptrAddr := self._arm64Utils.getStubLdrAddr(stubAddr)) is not None:
								stubNames = [
									sym for sym, ptrs in symbolPtrs.items() if ptrAddr in ptrs
								]
								pass
							pass

						# If the stub is optimized,
						# try to symbolize it though its target function
						if not stubNames:
							stubTarget = self._arm64Utils.resolveStubChain(stubAddr)
							stubNames = self._symbolizer.symbolizeAddr(stubTarget)
							pass

						if not stubNames:
							self._logger.warning(f"Unable to symbolize stub at {hex(stubAddr)}")
							continue

						for name in stubNames:
							_addToMap(name, stubAddr)

						# Try to find a symbol pointer for the stub
						symPtrAddr = None

						# if the stub is not optimized,
						# we can match it though the ldr instruction
						symPtrAddr = self._arm64Utils.getStubLdrAddr(stubAddr)

						# Try to match a pointer though symbols
						if not symPtrAddr:
							symPtrAddr = next(
								(symbolPtrs[sym][0] for sym in symbolPtrs if sym in stubNames),
								None
							)
							pass

						if not symPtrAddr:
							self._logger.warning(f"Unable to find a symbol pointer for stub at {hex(stubAddr)}, with names {stubNames}")  # noqa
							continue

						# relink the stub if necessary
						if stubData := self._arm64Utils.resolveStub(stubAddr):
							stubFormat = stubData[1]
							if stubFormat == _StubFormat.StubNormal:
								# No fix needed
								continue

							elif stubFormat == _StubFormat.StubOptimized:
								# only need to relink stub
								newStub = self._arm64Utils.generateStubNormal(stubAddr, symPtrAddr)
								self._machoCtx.writeBytes(
									self._dyldCtx.convertAddr(stubAddr),
									newStub
								)
								continue

							elif stubFormat == _StubFormat.AuthStubNormal:
								# only need to relink symbol pointer
								self._machoCtx.writeBytes(
									self._dyldCtx.convertAddr(symPtrAddr),
									struct.pack("<Q", stubAddr)
								)
								continue

							elif stubFormat == _StubFormat.AuthStubOptimized:
								# need to relink both the stub and the symbol pointer
								self._machoCtx.writeBytes(
									self._dyldCtx.convertAddr(symPtrAddr),
									struct.pack("<Q", stubAddr)
								)

								newStub = self._arm64Utils.generateAuthStubNormal(stubAddr, symPtrAddr)
								self._machoCtx.writeBytes(
									self._dyldCtx.convertAddr(stubAddr),
									newStub
								)
								continue

							elif stubFormat == _StubFormat.AuthStubResolver:
								# These shouldn't need fixing but check just in case
								if not self._machoCtx.containsAddr(stubData[0]):
									self._logger.error(f"Unable to fix auth stub resolver at {hex(stubAddr)}")  # noqa
								continue

							elif stubFormat == _StubFormat.Resolver:
								# how did we get here???
								self._logger.warning(f"Encountered a resolver at {hex(stubAddr)} while fixing stubs")  # noqa
								continue

							else:
								self._logger.error(f"Unknown stub format: {stubFormat}, at {hex(stubAddr)}")  # noqa
								continue
						else:
							self._logger.warning(f"Unknown stub format at {hex(stubAddr)}")
							continue
					pass
				pass
			pass

		return stubMap

	def _fixCallsites(self, stubMap: dict[bytes, tuple[int]]) -> None:
		if (
			b"__TEXT" not in self._machoCtx.segments
			or b"__text" not in self._machoCtx.segments[b"__TEXT"].sects
		):
			raise _StubFixerError("Unable to get __text section.")

		textSect = self._machoCtx.segments[b"__TEXT"].sects[b"__text"]

		textAddr = textSect.addr
		# Section offsets by section_64.offset are sometimes
		# inaccurate, like in libcrypto.dylib
		textOff = self._dyldCtx.convertAddr(textAddr)

		for sectOff in range(0, textSect.size, 4):
			# We are only looking for bl and b instructions only.
			# Theses instructions are only identical by their top
			# most byte. By only looking at the top byte, we can
			# save a lot of time.
			instrOff = textOff + sectOff
			instrTop = self._machoCtx.file[instrOff + 3] & 0xFC

			if (
				instrTop != 0x94  # bl
				and instrTop != 0x14  # b
			):
				continue

			# get the target of the branch
			brInstr = self._machoCtx.readFormat(instrOff, "<I")[0]
			imm26 = brInstr & 0x3FFFFFF
			brOff = self._arm64Utils.signExtend(imm26 << 2, 28)

			brAddr = textAddr + sectOff
			brTarget = brAddr + brOff

			# check if it needs fixing
			if self._machoCtx.containsAddr(brTarget):
				continue

			# find the matching stub for the branch
			brTargetFunc = self._arm64Utils.resolveStubChain(brTarget)
			if not (funcSymbols := self._symbolizer.symbolizeAddr(brTargetFunc)):
				# Sometimes there are bytes of data in the text section
				# that match the bl and b filter, these seem to follow a
				# BR or other branch, skip these.
				lastInstTop = self._machoCtx.file[instrOff + 3] & 0xFC
				if (
					lastInstTop == 0x94  # bl
					or lastInstTop == 0x14  # b
					or lastInstTop == 0xD6  # br
				):
					continue

				self._logger.warning(f"Unable to symbolize branch at {hex(brAddr)}, targeting {hex(brTargetFunc)}")  # noqa
				continue

			stubSymbol = next((sym for sym in funcSymbols if sym in stubMap), None)
			if not stubSymbol:
				# Same as above
				lastInstTop = self._machoCtx.file[instrOff + 3] & 0xFC
				if (
					lastInstTop == 0x94  # bl
					or lastInstTop == 0x14  # b
					or lastInstTop == 0xD6  # br
				):
					continue

				self._logger.warning(f"Unable to find a stub for branch at {hex(brAddr)}, potential symbols: {funcSymbols}")  # noqa
				continue

			# repoint the branch to the stub
			stubAddr = stubMap[stubSymbol][0]
			imm26 = (stubAddr - brAddr) >> 2
			brInstr = (brInstr & 0xFC000000) | imm26
			struct.pack_into("<I", self._machoCtx.file, instrOff, brInstr)

			self._statusBar.update(status="Fixing Callsites")
			pass
		pass

	def _fixIndirectSymbols(
		self,
		symbolPtrs: dict[bytes, tuple[int]],
		stubMap: dict[bytes, tuple[int]]
	) -> None:
		"""Fix indirect symbols.

		Some files have indirect symbols that are redacted,
		These are then pointed to the "redacted" symbol entry.
		But disassemblers like Ghidra use these to symbolize
		stubs and other pointers.
		"""

		if not self._extractionCtx.hasRedactedIndirect:
			return

		self._statusBar.update(status="Fixing Indirect Symbols")

		currentSymbolIndex = self._dysymtab.iundefsym + self._dysymtab.nundefsym
		currentStringIndex = self._symtab.strsize

		newSymbols = bytearray()
		newStrings = bytearray()

		for seg in self._machoCtx.segmentsI:
			for sect in seg.sectsI:
				sectType = sect.flags & SECTION_TYPE

				if sectType == S_SYMBOL_STUBS:
					indirectStart = sect.reserved1
					indirectEnd = sect.reserved1 + int(sect.size / sect.reserved2)
					for i in range(indirectStart, indirectEnd):
						self._statusBar.update()

						entryOffset = self._dysymtab.indirectsymoff + (i * 4)
						entry = self._machoCtx.readFormat(entryOffset, "<I")[0]

						if entry != 0:
							continue

						stubAddr = sect.addr + ((i - indirectStart) * sect.reserved2)
						stubSymbol = next(
							(sym for (sym, ptrs) in stubMap.items() if stubAddr in ptrs),
							None
						)
						if not stubSymbol:
							self._logger.warning(f"Unable to symbolize indirect stub symbol at {hex(stubAddr)}, indirect symbol index {i}")  # noqa
							continue

						# create the entry and add the string
						newSymbolEntry = nlist_64()
						newSymbolEntry.n_type = 1
						newSymbolEntry.n_strx = currentStringIndex

						newStrings.extend(stubSymbol)
						currentStringIndex += len(stubSymbol)

						# update the indirect entry and add it
						self._machoCtx.writeBytes(
							entryOffset,
							struct.pack("<I", currentSymbolIndex)
						)

						newSymbols.extend(newSymbolEntry)
						currentSymbolIndex += 1
						pass
					pass

				elif (
					sectType == S_NON_LAZY_SYMBOL_POINTERS
					or sectType == S_LAZY_SYMBOL_POINTERS
				):
					indirectStart = sect.reserved1
					indirectEnd = sect.reserved1 + int(sect.size / 8)

					for i in range(indirectStart, indirectEnd):
						self._statusBar.update()

						entryOffset = self._dysymtab.indirectsymoff + (i * 4)
						entry = self._machoCtx.readFormat(entryOffset, "<I")[0]

						if entry != 0:
							continue

						ptrAddr = sect.addr + ((i - indirectStart) * 8)
						ptrSymbol = next(
							(sym for (sym, ptrs) in symbolPtrs.items() if ptrAddr in ptrs),
							None
						)
						if not ptrSymbol:
							self._logger.warning(f"Unable to symbolize pointer at {hex(ptrAddr)}, indirect entry index {i}")  # noqa
							continue

						# create the entry and add the string
						newSymbolEntry = nlist_64()
						newSymbolEntry.n_type = 1
						newSymbolEntry.n_strx = currentStringIndex

						newStrings.extend(ptrSymbol)
						currentStringIndex += len(ptrSymbol)

						# update the indirect entry and add it
						self._machoCtx.writeBytes(
							entryOffset,
							struct.pack("<I", currentSymbolIndex)
						)

						newSymbols.extend(newSymbolEntry)
						currentSymbolIndex += 1
						pass
					pass

				elif (
					sectType == S_MOD_INIT_FUNC_POINTERS
					or sectType == S_MOD_TERM_FUNC_POINTERS
				):
					indirectStart = sect.reserved1
					indirectEnd = sect.reserved1 + int(sect.size / 8)

					for i in range(indirectStart, indirectEnd):
						self._statusBar.update()

						entryOffset = self._dysymtab.indirectsymoff + (i * 4)
						entry = self._machoCtx.readFormat(entryOffset, "<I")[0]

						if entry != 0:
							continue

						raise NotImplementedError
					pass

				elif sectType == S_16BYTE_LITERALS:
					indirectStart = sect.reserved1
					indirectEnd = sect.reserved1 + int(sect.size / 16)

					for i in range(indirectStart, indirectEnd):
						self._statusBar.update()

						entryOffset = self._dysymtab.indirectsymoff + (i * 4)
						entry = self._machoCtx.readFormat(entryOffset, "<I")[0]

						if entry != 0:
							continue

						raise NotImplementedError
					pass

				elif sectType == S_DTRACE_DOF:
					continue

				elif (
					sectType == S_LAZY_DYLIB_SYMBOL_POINTERS
					or sectType == S_COALESCED
					or sectType == S_GB_ZEROFILL
					or sectType == S_INTERPOSING
				):
					raise NotImplementedError
				pass
			pass

		self._statusBar.update()

		# add the new data and update the load commands
		self._machoCtx.writeBytes(
			self._symtab.symoff + (self._symtab.nsyms * nlist_64.SIZE),
			newSymbols
		)
		self._machoCtx.writeBytes(
			self._symtab.stroff + self._symtab.strsize,
			newStrings
		)

		newSymbolsCount = int(len(newSymbols) / nlist_64.SIZE)
		newStringSize = len(newStrings)

		self._symtab.nsyms += newSymbolsCount
		self._symtab.strsize += newStringSize
		self._dysymtab.nundefsym += newSymbolsCount

		linkedit = self._machoCtx.segments[b"__LINKEDIT"].seg
		linkedit.vmsize += newStringSize
		linkedit.filesize += newStringSize

		self._statusBar.update()
		pass
	pass


def fixStubs(extractionCtx: ExtractionContext) -> None:
	extractionCtx.statusBar.update(unit="Stub Fixer")

	try:
		_StubFixer(extractionCtx).run()
	except _StubFixerError as e:
		extractionCtx.logger.error(f"Unable to fix stubs, reason: {e}")
	pass
