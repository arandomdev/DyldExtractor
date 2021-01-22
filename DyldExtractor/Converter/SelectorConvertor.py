import logging
import struct
import typing

from DyldExtractor import MachO, Dyld

class SelectorConverter(object):
	"""
		Fixes direct selector loading.
	"""
	
	def __init__(self, machoFile: MachO.MachoFile, dyldFile: Dyld.DyldFile) -> None:
		self.machoFile = machoFile
		self.dyldFile = dyldFile

		self.selectorCache: typing.Dict[bytes, int] = {}
	
	def enumerateSelrefs(self) -> bool:
		selrefs = self.machoFile.getSegment(b"_", b"__objc_selrefs\x00")[1]
		if not selrefs:
			return False
		
		for i in range(0, selrefs.size, 8):
			selrefTarget = struct.unpack_from("<Q", selrefs.sectionData, i)[0]
			selrefTarget &= 0xffffffffff
			selector = self.dyldFile.readString(self.dyldFile.convertAddr(selrefTarget))

			self.selectorCache[selector] = selrefs.addr + i
		return True

	def convert(self) -> None:
		success = self.enumerateSelrefs()
		if not success:
			logging.error("Can't get selrefs section")
			return

		textSect = self.machoFile.getSegment(b"__TEXT\x00", b"__text\x00")[1]
		textData = bytearray(textSect.sectionData)

		for i in range(0, textSect.size-4, 4):
			# an adrp then add instruction
			adrpInstr = struct.unpack_from("<I", textData, i)[0]
			if (adrpInstr & 0x9f000000) != 0x90000000:
				continue

			addInstr = struct.unpack_from("<I", textData, i+4)[0]
			if (addInstr & 0x7f000000) != 0x11000000:
				continue

			# verify that they go together
			adrpOutput = adrpInstr & 0x1f
			addInput = (addInstr >> 5) & 0x1f
			if adrpOutput != addInput:
				continue

			# get adrp
			adrpImmLo = (adrpInstr >> 29) & 0x3
			adrpImmHi = (adrpInstr >> 5) & 0x0007ffff
			adrpImm = ((adrpImmHi << 2) | adrpImmLo) << 12

			# 32bit signed int
			if adrpImm & (1 << 32):
				adrpImm -= 1 << 33
			
			adrp = ((textSect.addr + i) & ~0xfff) + adrpImm

			# get add
			add = (addInstr >> 10) & 0xfff

			target = adrp + add
			if not self.machoFile.containsAddr(target):
				targetOff = self.dyldFile.convertAddr(target)
				if targetOff == -1:
					logging.warning("Invalid address for target: " + str(target))
					continue
				selector = self.dyldFile.readString(targetOff)

				if not selector in self.selectorCache:
					if selector != b'\x00':
						logging.warning("No selref for: " + str(selector))
					continue

				selrefAddr = self.selectorCache[selector]
				
				# adjust the instructions to point to the selref
				# adrp
				adrpPC = (textSect.addr + i) & ~0xfff
				adrpImm = ((selrefAddr & ~0xfff) - adrpPC) >> 12
				adrpImmLo = (adrpImm & 0x3) << 29
				adrpImmHi = (adrpImm >> 2) << 5
				adrp = 0x90000000 | adrpImmLo | adrpImmHi | adrpOutput # adrp adrpOutput [imm + PC]

				# ldr
				ldrImm = selrefAddr & 0xfff
				ldrImm >>= 3 # scale
				ldrImm <<= 10
				ldrOutput = addInstr & 0x1f
				ldr = 0xf9400000 | ldrImm | (addInput << 5) | ldrOutput # ldr ldrOutput [imm + addInput]

				struct.pack_into("<I", textData, i, adrp)
				struct.pack_into("<I", textData, i + 0x4, ldr)
		
		textSect.sectionData = bytes(textData)