import logging
import struct
import typing

from DyldExtractor import Dyld
from DyldExtractor import MachO
from DyldExtractor import Uleb128

SPECIAL_STUB = {
	b"_fmodl\x00" : b"_fmod\x00",
	b"__platform_bzero\x00" : b"_bzero\x00",
	b"__platform_strnlen\x00" : b"_strnlen\x00",
	b"__platform_strstr\x00" : b"_strstr\x00",
	b"_fstatat64\x00" : b"_fstatat\x00",
	b"_flsll\x00" : b"_flsl\x00",
	b"_getfsstat64\x00" : b"_getfsstat\x00",
	b"_sendto$NOCANCEL\x00" : b"___sendto_nocancel\x00",
	b"_recvfrom$NOCANCEL\x00" : b"___recvfrom_nocancel\x00",
	b"_recvfrom\x00" : b"___recvfrom\x00",
	b"_sendto\x00" : b"___sendto\x00",
	b"__platform_strlcpy\x00" : b"_strlcpy\x00",
	b"__platform_strlcat\x00" : b"_strlcat\x00",
	b"__platform_memset_pattern16\x00" : b"_memset_pattern16\x00",
	b"__platform_memset_pattern8\x00" : b"_memset_pattern8\x00",
	b"__platform_memset_pattern4\x00" : b"_memset_pattern4\x00",
	b"_posix_madvise\x00" : b"_madvise\x00",
	# b"__platform_memcmp\x00" : b"_memcmp\x00", ???
	b"___fpclassifyl\x00" : b"___fpclassifyd\x00",
	b"_expl\x00" : b"_exp\x00",
	b"_logl\x00" : b"_log\x00",
	b"_powl\x00" : b"_pow\x00",
	# b"_scalbnl\x00" : b"_scalbn\x00", ??
	b"_log10l\x00" : b"_log10\x00",
	b"_exp2l\x00" : b"_exp2\x00",
	b"_tanhl\x00" : b"_tanh\x00",
	b"_log2l\x00" : b"_log2\x00",
	b"_atan2l\x00" : b"_atan2\x00",
	b"_cosl\x00" : b"_cos\x00",
	b"_sinl\x00" : b"_sin\x00",
	b"_tanl\x00" : b"_tan\x00",
	b"_asinl\x00" : b"_asin\x00",
	b"_hypotl\x00" : b"_hypot\x00",
	b"_acosl\x00" : b"_acos\x00",
	b"_atanl\x00" : b"_atan\x00",
	b"_cbrtl\x00" : b"_cbrt\x00",
	b"_erfl\x00" : b"_erf\x00",
	b"_erfcl\x00" : b"_erfc\x00",
	b"_vvexpf_\x00" : b"_vvexpf\x00",
	b"_vvtanhf_\x00" : b"_vvtanhf\x00",
	b"_vvceilf_\x00" : b"_vvceilf\x00",
	b"_vvcosf_\x00" : b"_vvcosf\x00",
	b"_vvdivf_\x00" : b"_vvdivf\x00",
	b"_vvexp2f_\x00" : b"_vvexp2f\x00",
	b"_vvfloorf_\x00" : b"_vvfloorf\x00",
	b"_vvpowf_\x00" : b"_vvpowf\x00",
	b"_vvsinf_\x00" : b"_vvsinf\x00",
	b"_vvlogf_\x00" : b"_vvlogf\x00",
	b"_vvpowsf_\x00" : b"_vvpowsf\x00",
	b"_nanl\x00" : b"_nan\x00",
	b"_coshl\x00" : b"_cosh\x00",
	# b"_nexttowardl\x00" : b"_nexttoward\x00", ???
	b"_remainderl\x00" : b"_remainder\x00",
	b"_sinhl\x00" : b"_sinh\x00",
	b"_vvintf_\x00" : b"_vvintf\x00",
	b"_vvnintf_\x00" : b"_vvnintf\x00",
	b"_vvsqrtf_\x00" : b"_vvsqrtf\x00",
	b"_logbl\x00" : b"_logb\x00",
	b"_expm1l\x00" : b"_expm1\x00",
	b"_acoshl\x00" : b"_acosh\x00",
	b"_asinhl\x00" : b"_asinh\x00",
	b"_atanhl\x00" : b"_atanh\x00",
	b"_log1pl\x00" : b"_log1p\x00",
	# b"\x00" : b"\x00",
}

class StubConverter(object):
	"""
		A converter related to stubs.
	"""

	imageCache: typing.List[MachO.MachoFile] = []
	
	def __init__(self, machoFile: MachO.MachoFile, dyldFile: Dyld.DyldFile) -> None:
		self.machoFile = machoFile
		self.dyldFile = dyldFile

		# cache that links a chain stub to the last stub 
		self.resolveCache: typing.Dict[int, int] = {}

		# cache that links a functions address to its name
		self.symbolCache: typing.Dict[int, bytes] = {}

		# cache that links a symbol name to the macho file's stub for
		# that symbol
		self.symbolToStubAddr: typing.Dict[bytes, int] = {}

	def convert(self) -> None:
		if not len(self.imageCache):
			self.enumerateImages()

		# make sure that the stub_helpers are in a supported format
		STUB_HELPER_START = 0x18
		stubHelperSect = self.machoFile.getSegment(b"__TEXT\x00", b"__stub_helper\x00")[1]
		if not stubHelperSect:
			return

		firstInstr = struct.unpack_from("<I", stubHelperSect.sectionData, STUB_HELPER_START)[0]
		isLdr = (firstInstr & 0xbf000000) == 0x18000000
		if not isLdr:
			return

		self.relinkTriad()
		self.fixCallsites()

	def enumerateImages(self) -> None:
		"""
			Caches every image in the dyld cache.
		"""

		for image in self.dyldFile.images:
			depOff = self.dyldFile.convertAddr(image.address)
			dep = MachO.MachoFile.parse(self.dyldFile.file, depOff, loadData=False)
			self.imageCache.append(dep)
	
	def readLazyBind(self, offset: int) -> typing.Tuple[int, int, bytes]:
		"""
			Reads the OPCODE_SET_SEGMENT_AND_OFFSET_ULEB and 
			OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM from the
			lazy bind info at the given offset.
		"""

		dyldInfo = self.machoFile.getLoadCommand((MachO.LoadCommands.LC_DYLD_INFO, MachO.LoadCommands.LC_DYLD_INFO_ONLY))
		lazyBindData = dyldInfo.lazy_bindData

		segIndex = None
		segOff = None
		flags = None

		# assume that OPCODE_SET_SEGMENT_AND_OFFSET_ULEB comes first
		# and then OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
		while offset < dyldInfo.lazy_bind_size:
			imm = lazyBindData[offset] & MachO.Bind.BIND_IMMEDIATE_MASK
			opcode = lazyBindData[offset] & MachO.Bind.BIND_OPCODE_MASK
			offset += 1

			if opcode == MachO.Bind.BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
				segIndex = imm

				segOff, ulebLen = Uleb128.readUleb128(lazyBindData, offset)
				offset += ulebLen
			elif opcode == MachO.Bind.BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
				flagsEnd = lazyBindData.index(b"\x00", offset) + 1
				flags = lazyBindData[offset:flagsEnd]
				break
		
		if segIndex is None or segOff is None or flags is None:
			raise Exception("Incorrect parsing")

		return (segIndex, segOff, flags)
	
	def stubTarget(self, stubAddr: int) -> int:
		"""
			Gets the target of a stub given a VMAddress.

			supports the instructions (adrp, add, br) or
			(adrp, ldr, br).

		"""
		
		stubFileOff = self.dyldFile.convertAddr(stubAddr)
		self.dyldFile.file.seek(stubFileOff)
		stubData = self.dyldFile.file.read(0xc) # the size of a stub

		adrpInstr = struct.unpack_from("<I", stubData, 0)[0]
		offInstr = struct.unpack_from("<I", stubData, 0x4)[0]
		brInstr = struct.unpack_from("<I", stubData, 0x8)[0]

		isAdrp = (adrpInstr & 0x9f000000) == 0x90000000
		isAdd = (offInstr & 0x7f000000) == 0x11000000
		isLdr = (offInstr & 0xbfc00000) == 0xb9400000
		isBr = (brInstr & 0xfffffc1f) == 0xd61f0000

		if (
			not isAdrp
			or (
				not isAdd
				and not isLdr
			)
			or not isBr
		):
			return -1
		
		adrpImmLo = (adrpInstr >> 29) & 0x3
		adrpImmHi = (adrpInstr >> 5) & 0x0007ffff
		adrpImm = ((adrpImmHi << 2) | adrpImmLo) << 12

		# 32bit signed int
		if adrpImm & (1 << 32):
			adrpImm -= 1 << 33
		
		adrp = (stubAddr & ~0xfff) + adrpImm

		offset = None
		if isAdd:
			offset = (offInstr >> 10) & 0xfff
		elif isLdr:
			imm = (offInstr >> 10) & 0xfff
			scale = offInstr >> 30
			offset = imm << scale
		else:
			return -1
		
		return adrp + offset
	
	def la_resolverTarget(self, ptrAddr: int) -> None:
		"""
		Finds the target of a __la_resolver and special __stub_helper pair.

		Parameters
		----------
			ptrAddr : int
				The address of the __la_resolver pointer.
		"""

		self.dyldFile.file.seek(self.dyldFile.convertAddr(ptrAddr))
		stubHelperAddr = struct.unpack("<Q", self.dyldFile.file.read(8))[0]
		stubHelperAddr &= 0xffffffffff
		stubHelperOff = self.dyldFile.convertAddr(stubHelperAddr)

		# get the target of the BL instruction
		BL_OFFSET = 0x18
		self.dyldFile.file.seek(stubHelperOff + BL_OFFSET)
		blInstr = struct.unpack("<I", self.dyldFile.file.read(4))[0]

		# verify that it is a bl instruction
		if (blInstr & 0xfc000000) != 0x94000000:
			return -1

		blImm = blInstr & 0x3ffffff
		if blImm & (1 << 25):
			blImm -= (1 << 26)
		blImm <<= 2
		
		target = blImm + (stubHelperAddr + BL_OFFSET)
		return target
	
	def resolveTarget(self, initialStub: int) -> int:
		"""Gives the final target of a stub chain.

		This method will follow the chian of stub
		calls until it hits a function. This will
		usually return a function address that is
		available in the symbolCache.

		Parameters
		----------
			initialStub : int
				The address to the stub.

		Returns
		-------
			int
				The final target.
		"""

		# check the cache
		if initialStub in self.resolveCache:
			return self.resolveCache[initialStub]
		
		stubChain = []

		currentAddr = initialStub
		while True:
			nextAddr = self.stubTarget(currentAddr)

			if nextAddr == -1:
				# check if we hit a function
				image = next(image for image in self.imageCache if image.containsAddr(currentAddr))
				sect = image.segmentForAddr(currentAddr)[1]

				if (
					b"__la_resolver\x00" in sect.sectname
					or b"__data\x00" in sect.sectname
				):
					# the stub should be right before this
					stubAddr = stubChain[-1]
					self.resolveCache[initialStub] = stubAddr
					return stubAddr
				else:
					self.resolveCache[initialStub] = currentAddr
					return currentAddr
			else:
				stubChain.append(currentAddr)
				currentAddr = nextAddr
				pass
	
	def lookupSymbol(self, addr: int) -> bytes:
		"""
			Given the VMAddress of an exported function,
			this method will return its symbol name.
		"""

		if addr in self.symbolCache:
			return self.symbolCache[addr]
		
		# find the image with the address and cache its exports.
		for image in self.imageCache:
			if image.containsAddr(addr):
				dyldInfo = image.getLoadCommand((MachO.LoadCommands.LC_DYLD_INFO, MachO.LoadCommands.LC_DYLD_INFO_ONLY))
				dyldInfo.loadData()

				imageTextSeg = image.getSegment(b"__TEXT\x00")

				exports =  MachO.TrieParser(dyldInfo.exportData).parse()
				for export in exports:
					exportAddr = imageTextSeg.vmaddr + export.address
					self.symbolCache[exportAddr] = export.name
				break
		
		# look for the symbol again
		if addr in self.symbolCache:
			return self.symbolCache[addr]
		else:
			return None

	def relinkTriad(self) -> None:
		"""
			relinks the stubs, stub helpers, and lazy symbol pointers.
		"""

		# interate though the stub helpers and link the lazy symbol pointers.
		STUB_HELPER_START = 0x18
		STUB_HELPER_SIZE = 0xc
		STUB_HELPER_DATA_OFF = 0x8

		stubHelperSect = self.machoFile.getSegment(b"__TEXT\x00", b"__stub_helper\x00")[1]
		stubHelperData = stubHelperSect.sectionData

		laSymPtrSect = self.machoFile.getSegment(b"__DATA_CONST\x00", b"__la_symbol_ptr\x00")[1]
		laSymPtrData = bytearray(laSymPtrSect.sectionData)

		symToLaPtr: typing.Dict[bytes, int] = {}
		for i in range(STUB_HELPER_START, stubHelperSect.size, STUB_HELPER_SIZE):
			lazyBindOff = struct.unpack_from("<I", stubHelperData, i + STUB_HELPER_DATA_OFF)[0]
			bindData = self.readLazyBind(lazyBindOff)

			try:
				laSymPtrAddr = self.machoFile.loadCommands[bindData[0]].vmaddr + bindData[1]
			except:
				continue

			laSymPtrSectOff = laSymPtrAddr - laSymPtrSect.addr
			stubHelperAddr = stubHelperSect.addr + i

			try:
				struct.pack_into("<Q", laSymPtrData, laSymPtrSectOff, stubHelperAddr)
			except:
				continue

			symToLaPtr[bindData[2]] = laSymPtrAddr

		laSymPtrSect.sectionData = bytes(laSymPtrData)

		# link stubs to the lazy symbol pointers
		STUB_SIZE = 0xc

		stubSect = self.machoFile.getSegment(b"__TEXT\x00", b"__stubs\x00")[1]
		stubData = bytearray(stubSect.sectionData)

		for i in range(0, stubSect.size, STUB_SIZE):
			stubAddr = i + stubSect.addr
			functionAddr = self.resolveTarget(stubAddr)

			# get the symbol and cache it
			if self.machoFile.containsAddr(functionAddr):
				for sym, laPtr in symToLaPtr.items():
					if laPtr == functionAddr:
						self.symbolToStubAddr[sym] = stubAddr
						break
				continue

			symbol = self.lookupSymbol(functionAddr)
			self.symbolToStubAddr[symbol] = stubAddr

			laSymPtrAddr = None
			if symbol in symToLaPtr:
				laSymPtrAddr = symToLaPtr[symbol]
			elif symbol in SPECIAL_STUB:
				laSymPtrAddr = symToLaPtr[SPECIAL_STUB[symbol]]
			else:
				logging.warning("No lazy symbol pointer for symbol: " + str(symbol))
				continue

			# re link the optimized stub
			# adrp
			adrpPC = stubAddr & ~0xfff
			adrpImm = ((laSymPtrAddr & ~0xfff) - adrpPC) >> 12
			adrpImmLo = (adrpImm & 0x3) << 29
			adrpImmHi = (adrpImm >> 2) << 5
			adrp = 0x90000010 | adrpImmLo | adrpImmHi # adrp x16

			# ldr
			ldrImm = laSymPtrAddr & 0xfff
			ldrImm >>= 3 # scale
			ldrImm <<= 10
			ldr = 0xf9400210 | ldrImm # ldr x16 [x16 + imm]

			struct.pack_into("<I", stubData, i, adrp)
			struct.pack_into("<I", stubData, i + 0x4, ldr)
		
		stubSect.sectionData = bytes(stubData)
	
	def fixCallsites(self):
		"""
			Re-points branch calls back to the stubs.
		"""

		textSect = self.machoFile.getSegment(b"__TEXT\x00", b"__text\x00")[1]
		textData = bytearray(textSect.sectionData)

		for i in range(0, textSect.size, 4):
			instr = struct.unpack_from("<I", textData, i)[0]
			instrAddr = i + textSect.addr

			# skip all but bl or b
			if (instr & 0x7c000000) != 0x14000000:
				continue

			# get the target of the branch
			brImm = instr & 0x03ffffff
			if brImm & (1 << 25):
				brImm -= 1 << 26
			target = (brImm << 2) + instrAddr

			if not self.machoFile.containsAddr(target):
				targetFunc = self.resolveTarget(target)
				targetSym = None

				targetSym = self.lookupSymbol(targetFunc)
				if targetSym is None:
					logging.warning("No symbol for: " + hex(targetFunc))
					continue

				stubAddr = None
				if targetSym in self.symbolToStubAddr:
					stubAddr = self.symbolToStubAddr[targetSym]
				elif targetSym in SPECIAL_STUB:
					stubAddr = self.symbolToStubAddr[SPECIAL_STUB[targetSym]]
				else:
					logging.warning("No stub addr for: " + str(targetSym))
					continue

				# point the branch instruction to the stub
				brImm = (stubAddr - instrAddr) >> 2
				brInstr = (instr & 0xfc000000) | brImm
				struct.pack_into("<I", textData, i, brInstr)
		
		textSect.sectionData = bytes(textData)
		pass