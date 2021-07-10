import struct

from DyldExtractor.extraction_context import ExtractionContext
from DyldExtractor.converter import (
	slide_info,
	stub_fixer
)

from DyldExtractor.objc.objc_structs import (
	objc_category_t,
	objc_class_data_t,
	objc_class_t,
	objc_ivar_list_t,
	objc_ivar_t,
	objc_method_large_t,
	objc_method_list_t,
	objc_method_small_t,
	objc_property_list_t,
	objc_property_t,
	objc_protocol_list_t,
	objc_protocol_t
)

from DyldExtractor.macho.macho_context import MachOContext
from DyldExtractor.macho.macho_structs import (
	LoadCommands,
	linkedit_data_command,
	mach_header_64,
	segment_command_64
)


class _ObjCFixerError(Exception):
	pass


class _ObjCFixer(object):

	def __init__(self, extractionCtx: ExtractionContext) -> None:
		super().__init__()

		self._extractionCtx = extractionCtx
		self._dyldCtx = extractionCtx.dyldCtx
		self._machoCtx = extractionCtx.machoCtx
		self._statusBar = extractionCtx.statusBar
		self._logger = extractionCtx.logger

		self._slider = slide_info.PointerSlider(extractionCtx)
		pass

	def run(self):
		# check if the optimization flag is set
		imageInfo = None
		for seg in self._machoCtx.segmentsI:
			if b"__objc_imageinfo" in seg.sects:
				imageInfo = seg.sects[b"__objc_imageinfo"]
				break
			pass

		if not imageInfo:
			return

		flags = self._machoCtx.readFormat(
			self._dyldCtx.convertAddr(imageInfo.addr) + 4,
			"<I"
		)[0]
		if not flags & 0x8:
			self._logger.info("ObjC was not optimized by Dyld, not fixing ObjC.")
			return

		self._createExtraSegment()

		# caches that map the original definition address
		# to its new processed address.
		self._categoryCache: dict[int, int] = {}
		self._classCache: dict[int, int] = {}
		self._classDataCache: dict[int, int] = {}
		self._ivarListCache: dict[int, int] = {}
		self._protocolListCache: dict[int, int] = {}
		self._protocolCache: dict[int, int] = {}
		self._propertyListCache: dict[int, int] = {}
		self._methodListCache: dict[int, int] = {}
		self._stringCache: dict[int, int] = {}
		self._intCache: dict[int, int] = {}

		# connects a selrefs old target to its pointer address
		self._selRefCache: dict[int, int] = {}

		# A list of class pointers that are being processed.
		self._classesProcessing: list[int] = []

		# A list of pointers that need to be updated at the end
		# The first int is the address to the pointer that needs
		# to be changed. The second int is the address of the
		# target class
		self._futureClasses: list[tuple[int, int]] = []

		self._processSections()
		self._finalizeFutureClasses()
		self._fixSelectors()

		self._checkSpaceConstraints()
		self._addExtraDataSeg()
		pass

	def _createExtraSegment(self) -> None:
		"""Create an extra segment to store data in.
		"""

		# sort the segments and try to find the biggest space for the segment
		segments = [
			segment.seg
			for segment
			in sorted(self._machoCtx.segmentsI, key=lambda x: x.seg.vmaddr)
		]

		# check to make that __TEXT and __LINKEDIT segments are at the edges
		if segments[0].segname != b"__TEXT":
			raise _ObjCFixerError("MachO file does not start with __TEXT segment.")
		if segments[-1].segname != b"__LINKEDIT":
			raise _ObjCFixerError("MachO file does not end with __LINKEDIT segment.")

		# find the biggest gap
		maxGapSize = 0
		gapStart = 0
		for i in range(len(segments) - 1):
			gapStart = segments[i].vmaddr + segments[i].vmsize
			gapEnd = segments[i + 1].vmaddr
			gapSize = gapEnd - gapStart
			gapSize = (segments[i].vmaddr + segments[i].vmsize)

			if gapSize > maxGapSize:
				maxGapSize = gapSize
				leftSeg = segments[i]
				pass
			pass

		if maxGapSize == 0:
			raise _ObjCFixerError("Unable to find space for the extra ObjC segment.")

		# Get a starting address for the new segment
		newSegStartAddr = (leftSeg.vmaddr + leftSeg.vmsize + 0x1000) & ~0xFFF
		newSegStartOff = (
			self._dyldCtx.convertAddr(leftSeg.vmaddr) + leftSeg.vmsize
			+ 0x1000
		) & ~0xFFF

		# adjust max gap size to account for page alignment
		maxGapSize -= newSegStartAddr - (leftSeg.vmaddr + leftSeg.vmsize)

		# create the new segment
		newSegment = segment_command_64()
		newSegment.cmd = LoadCommands.LC_SEGMENT_64
		newSegment.cmdsize = segment_command_64.SIZE  # no sections
		newSegment.segname = b"__EXTRA_OBJC"
		newSegment.vmaddr = newSegStartAddr
		newSegment.fileoff = newSegStartOff
		newSegment.maxprot = 3  # read and write
		newSegment.initprot = 3  # read and write
		newSegment.nsects = 0
		newSegment.flags = 0

		self._extraSegment = newSegment
		self._extraDataMaxSize = maxGapSize
		self._extraDataHead = newSegStartAddr
		self._extraData = bytearray()
		pass

	def _processSections(self) -> None:
		for segment in self._machoCtx.segmentsI:
			for sect in segment.sectsI:

				if sect.sectname == b"__objc_classlist":
					for ptrAddr in range(sect.addr, sect.addr + sect.size, 8):
						self._statusBar.update(status="Processing Classes")
						classAddr = self._slider.slideAddress(ptrAddr)

						if self._machoCtx.containsAddr(classAddr):
							if self._processClass(classAddr)[1]:
								self._futureClasses.append((ptrAddr, classAddr))
								pass

							continue

						self._logger.warning(f"Class pointer at {hex(ptrAddr)} points to class outside MachO file.")  # noqa
					pass

				elif sect.sectname == b"__objc_catlist":
					for ptrAddr in range(sect.addr, sect.addr + sect.size, 8):
						self._statusBar.update(status="Processing Categories")
						categoryAddr = self._slider.slideAddress(ptrAddr)

						if self._machoCtx.containsAddr(categoryAddr):
							self._processCategory(categoryAddr)
							continue

						self._logger.warning(f"Category pointer at {hex(ptrAddr)} points to category outside MachO file.")  # noqa
					pass

				elif sect.sectname == b"__objc_protolist":
					for ptrAddr in range(sect.addr, sect.addr + sect.size, 8):
						self._statusBar.update(status="Processing Protocols")
						protoAddr = self._slider.slideAddress(ptrAddr)

						if self._machoCtx.containsAddr(protoAddr):
							self._processProtocol(protoAddr)
							continue

						self._logger.warning(f"Protocol pointer at {hex(ptrAddr)} points to protocol outside MachO file.")  # noqa
					pass

				elif sect.sectname == b"__objc_selrefs":
					for ptrAddr in range(sect.addr, sect.addr + sect.size, 8):
						self._statusBar.update(status="Processing Selector References")
						selRefAddr = self._slider.slideAddress(ptrAddr)

						self._selRefCache[selRefAddr] = ptrAddr

						newPtr = self._processString(selRefAddr)
						self._machoCtx.writeBytes(
							self._dyldCtx.convertAddr(ptrAddr),
							struct.pack("<Q", newPtr)
						)
						pass
					pass
				pass
			pass
		pass

	def _addExtraData(self, data: bytes) -> None:
		"""Adds the data to the extra data buffer.

		Automatically pointer aligns and updates the
		counter.
		"""

		data = bytes(data)
		if mod := len(data) % 8:
			data += b"\x00" * (8 - mod)
			pass

		self._extraData.extend(data)
		self._extraDataHead += len(data)
		pass

	def _processCategory(self, categoryAddr: int) -> int:
		if categoryAddr in self._categoryCache:
			return self._categoryCache[categoryAddr]

		categoryDef = self._slider.slideStruct(categoryAddr, objc_category_t)

		if categoryDef.name:
			categoryDef.name = self._processString(categoryDef.name)
			pass

		needsFutureClass = False
		if categoryDef.cls:
			categoryDef.cls, needsFutureClass = self._processClass(categoryDef.cls)
			pass

		if categoryDef.instanceMethods:
			categoryDef.instanceMethods = self._processMethodList(
				categoryDef.instanceMethods
			)
			pass

		if categoryDef.classMethods:
			categoryDef.classMethods = self._processMethodList(categoryDef.classMethods)
			pass

		if categoryDef.protocols:
			categoryDef.protocols = self._processProtocolList(categoryDef.protocols)
			pass

		if categoryDef.instanceProperties:
			categoryDef.instanceProperties = self._processPropertyList(
				categoryDef.instanceProperties
			)
			pass

		# Add or update data
		if self._machoCtx.containsAddr(categoryAddr):
			newCategoryAddr = categoryAddr

			defOff = self._dyldCtx.convertAddr(categoryAddr)
			self._machoCtx.writeBytes(defOff, categoryDef)
			pass
		else:
			newCategoryAddr = self._extraDataHead
			self._addExtraData(categoryDef)
			pass

		if needsFutureClass:
			futureClass = (
				newCategoryAddr + objc_category_t.cls.offset,
				categoryDef.cls
			)
			self._futureClasses.append(futureClass)
			pass

		self._categoryCache[categoryAddr] = newCategoryAddr
		return newCategoryAddr

	def _processClass(self, classAddr: int) -> tuple[int, bool]:
		"""Process a class definition.

		Args:
			defAddr: The address of the class definition.

		Returns:
			If the class if fully defined the updated address
			of the class is returned along with False. otherwise
			the original address of the class is returned, along
			with True.
		"""

		# check if the class is already being processed.
		if classAddr in self._classesProcessing:
			return classAddr, True

		# check if the class was processed before
		if classAddr in self._classCache:
			return self._classCache[classAddr], False

		self._classesProcessing.append(classAddr)
		classDef = self._slider.slideStruct(classAddr, objc_class_t)

		needsFutureIsa = False
		if classDef.isa:
			classDef.isa, needsFutureIsa = self._processClass(classDef.isa)
			pass

		needsFutureSuper = False
		if classDef.superclass:
			classDef.superclass, needsFutureSuper = self._processClass(
				classDef.superclass
			)
			pass

		# zero out cache and vtable
		classDef.method_cache = 0
		classDef.vtable = 0

		if classDef.data:
			# Low bit marks Swift classes
			isStubClass = not self._machoCtx.containsAddr(classAddr)
			classDef.data = self._processClassData(
				classDef.data & ~0x3,
				isStubClass=isStubClass
			)
			pass

		# add or update data
		if self._machoCtx.containsAddr(classAddr):
			newClassAddr = classAddr

			defOff = self._dyldCtx.convertAddr(classAddr)
			self._machoCtx.writeBytes(defOff, classDef)
			pass

		else:
			newClassAddr = self._extraDataHead
			self._addExtraData(classDef)
			pass

		# add any future pointers if necessary
		if needsFutureIsa:
			futureClass = (
				newClassAddr + objc_class_t.isa.offset,
				classDef.isa
			)
			self._futureClasses.append(futureClass)
			pass
		if needsFutureSuper:
			futureClass = (
				newClassAddr + objc_class_t.superclass.offset,
				classDef.superclass
			)
			self._futureClasses.append(futureClass)
			pass

		self._classesProcessing.remove(classAddr)
		self._classCache[classAddr] = newClassAddr
		return newClassAddr, False

	def _processClassData(self, classDataAddr: int, isStubClass=False) -> int:
		if classDataAddr in self._classDataCache:
			return self._classDataCache[classDataAddr]

		classDataDef = self._slider.slideStruct(classDataAddr, objc_class_data_t)

		if classDataDef.ivarLayout:
			classDataDef.ivarLayout = self._processInt(classDataDef.ivarLayout, 1)
			pass

		if classDataDef.name:
			classDataDef.name = self._processString(classDataDef.name)
			pass

		if classDataDef.baseMethods:
			classDataDef.baseMethods = self._processMethodList(
				classDataDef.baseMethods,
				noImp=isStubClass
			)
			pass

		if classDataDef.baseProtocols:
			classDataDef.baseProtocols = self._processProtocolList(
				classDataDef.baseProtocols
			)
			pass

		if classDataDef.ivars:
			classDataDef.ivars = self._processIvarList(classDataDef.ivars)
			pass

		if classDataDef.weakIvarLayout:
			classDataDef.weakIvarLayout = self._processInt(
				classDataDef.weakIvarLayout,
				1
			)
			pass

		if classDataDef.baseProperties:
			classDataDef.baseProperties = self._processPropertyList(
				classDataDef.baseProperties
			)
			pass

		# add or update data
		if self._machoCtx.containsAddr(classDataAddr):
			newClassDataAddr = classDataAddr

			defOff = self._dyldCtx.convertAddr(classDataAddr)
			self._machoCtx.writeBytes(defOff, classDataDef)
			pass

		else:
			newClassDataAddr = self._extraDataHead
			self._addExtraData(classDataDef)
			pass

		self._classDataCache[classDataAddr] = newClassDataAddr
		return newClassDataAddr

	def _processIvarList(self, ivarListAddr: int) -> int:
		if ivarListAddr in self._ivarListCache:
			return self._ivarListCache[ivarListAddr]

		ivarListDef = self._slider.slideStruct(ivarListAddr, objc_ivar_list_t)
		ivarListData = bytearray(ivarListDef)

		# check size
		if ivarListDef.entsize != objc_ivar_t.SIZE:
			self._logger.error(f"Ivar list at {hex(ivarListAddr)}, has an entsize that doesn't match objc_ivar_t")  # noqa
			return 0

		for i in range(ivarListDef.count):
			ivarAddr = (
				ivarListAddr
				+ objc_ivar_list_t.SIZE
				+ (i * ivarListDef.entsize)
			)

			ivarDef = self._slider.slideStruct(ivarAddr, objc_ivar_t)

			if ivarDef.offset:
				ivarDef.offset = self._processInt(ivarDef.offset, 4)
				pass

			if ivarDef.name:
				ivarDef.name = self._processString(ivarDef.name)
				pass

			if ivarDef.type:
				ivarDef.type = self._processString(ivarDef.type)
				pass

			ivarListData.extend(ivarDef)
			pass

		# add or update data
		if self._machoCtx.containsAddr(ivarListAddr):
			newIvarListAddr = ivarListAddr

			defOff = self._dyldCtx.convertAddr(ivarListAddr)
			self._machoCtx.writeBytes(defOff, ivarListData)
			pass
		else:
			newIvarListAddr = self._extraDataHead
			self._addExtraData(ivarListData)
			pass

		self._ivarListCache[ivarListAddr] = newIvarListAddr
		return newIvarListAddr

	def _processProtocolList(self, protoListAddr: int) -> int:
		if protoListAddr in self._protocolListCache:
			return self._protocolListCache[protoListAddr]

		protoListDef = self._slider.slideStruct(protoListAddr, objc_protocol_list_t)
		protoListData = bytearray(protoListDef)

		for i in range(protoListDef.count):
			protoAddr = self._slider.slideAddress(
				protoListAddr
				+ objc_protocol_list_t.SIZE
				+ (i * 8)
			)

			newProtoAddr = self._processProtocol(protoAddr)
			protoListData.extend(struct.pack("<Q", newProtoAddr))
			pass

		# Add or update data
		if self._machoCtx.containsAddr(protoListAddr):
			newProtoListAddr = protoListAddr

			defOff = self._dyldCtx.convertAddr(protoListAddr)
			self._machoCtx.writeBytes(defOff, protoListData)
			pass
		else:
			newProtoListAddr = self._extraDataHead
			self._addExtraData(protoListData)
			pass

		self._protocolListCache[protoListAddr] = newProtoListAddr
		return newProtoListAddr

	def _processProtocol(self, protoAddr: int) -> int:
		if protoAddr in self._protocolCache:
			return self._protocolCache[protoAddr]

		protoDef = self._slider.slideStruct(protoAddr, objc_protocol_t)

		# protocol isa's should be 0
		protoDef.isa = 0

		if protoDef.name:
			protoDef.name = self._processString(protoDef.name)
			pass

		if protoDef.protocols:
			protoDef.protocols = self._processProtocolList(protoDef.protocols)
			pass

		if protoDef.instanceMethods:
			protoDef.instanceMethods = self._processMethodList(
				protoDef.instanceMethods,
				noImp=True
			)
			pass

		if protoDef.classMethods:
			protoDef.classMethods = self._processMethodList(
				protoDef.classMethods,
				noImp=True
			)
			pass

		if protoDef.optionalInstanceMethods:
			protoDef.optionalInstanceMethods = self._processMethodList(
				protoDef.optionalInstanceMethods,
				noImp=True
			)
			pass

		if protoDef.optionalClassMethods:
			protoDef.optionalClassMethods = self._processMethodList(
				protoDef.optionalClassMethods,
				noImp=True
			)
			pass

		if protoDef.instanceProperties:
			protoDef.instanceProperties = self._processPropertyList(
				protoDef.instanceProperties
			)
			pass

		hasExtendedMethodTypes = protoDef.size < 80
		if protoDef.extendedMethodTypes and hasExtendedMethodTypes:
			# const char **extendedMethodTypes;
			oldPtr = self._slider.slideAddress(protoDef.extendedMethodTypes)
			newPtr = self._processString(oldPtr)

			if self._machoCtx.containsAddr(protoDef.extendedMethodTypes):
				ptrOff = self._dyldCtx.convertAddr(protoDef.extendedMethodTypes)
				struct.pack_into("<Q", self._machoCtx.file, ptrOff, newPtr)
				pass
			else:
				protoDef.extendedMethodTypes = self._extraDataHead

				ptrData = struct.pack("<Q", newPtr)
				self._addExtraData(ptrData)
				pass
			pass

		hasDemangledName = protoDef.size < 88
		if protoDef.demangledName and hasDemangledName:
			protoDef.demangledName = self._processString(protoDef.demangledName)
			pass

		hasClassProperties = protoDef.size < 96
		if protoDef.classProperties and hasClassProperties:
			protoDef.classProperties = self._processPropertyList(
				protoDef.classProperties
			)
			pass

		# Add or update data
		protoData = bytes(protoDef)[:protoDef.size]
		if self._machoCtx.containsAddr(protoAddr):
			newProtoAddr = protoAddr

			defOff = self._dyldCtx.convertAddr(protoAddr)
			self._machoCtx.writeBytes(defOff, protoData)
			pass
		else:
			newProtoAddr = self._extraDataHead
			self._addExtraData(protoData)
			pass

		self._protocolCache[protoAddr] = newProtoAddr
		return newProtoAddr

	def _processPropertyList(self, propertyListAddr: int) -> int:
		if propertyListAddr in self._propertyListCache:
			return self._propertyListCache[propertyListAddr]

		propertyListDef = self._slider.slideStruct(
			propertyListAddr,
			objc_property_list_t
		)

		# check size
		if propertyListDef.entsize != objc_property_t.SIZE:
			self._logger.error(f"Property list at {hex(propertyListAddr)} has an entsize that doesn't match objc_property_t")  # noqa
			return 0

		propertyListData = bytearray(propertyListDef)
		for i in range(propertyListDef.count):
			propertyAddr = (
				propertyListAddr
				+ propertyListDef.SIZE
				+ (i * propertyListDef.entsize)
			)

			propertyDef = self._slider.slideStruct(propertyAddr, objc_property_t)

			if propertyDef.name:
				propertyDef.name = self._processString(propertyDef.name)
				pass

			if propertyDef.attributes:
				propertyDef.attributes = self._processString(propertyDef.attributes)
				pass

			propertyListData.extend(propertyDef)
			pass

		# Add or update data
		if self._machoCtx.containsAddr(propertyListAddr):
			newPropertyListAddr = propertyListAddr

			defOff = self._dyldCtx.convertAddr(propertyListAddr)
			self._machoCtx.writeBytes(defOff, propertyListData)
			pass
		else:
			newPropertyListAddr = self._extraDataHead
			self._addExtraData(propertyListData)
			pass

		self._propertyListCache[propertyListAddr] = newPropertyListAddr
		return newPropertyListAddr

	def _processMethodList(self, methodListAddr: int, noImp=False) -> int:
		if methodListAddr in self._methodListCache:
			return self._methodListCache[methodListAddr]

		methodListDef = self._slider.slideStruct(methodListAddr, objc_method_list_t)

		methodListData = bytearray(methodListDef)
		usesRelativeMethods = methodListDef.usesRelativeMethods()
		entsize = methodListDef.getEntsize()

		# check if size is correct
		if usesRelativeMethods and entsize != objc_method_small_t.SIZE:
			self._logger.error(f"Small method list at {hex(methodListAddr)}, has an entsize that doesn't match the size of objc_method_small_t")  # noqa
			return 0
		elif not usesRelativeMethods and entsize != objc_method_large_t.SIZE:
			self._logger.error(f"Large method list at {hex(methodListAddr)}, has an entsize that doesn't match the size of objc_method_large_t")  # noqa
			return 0

		# fix relative pointers after we reserve a new address for the method list
		# contains a list of tuples of field offsets and their target addresses
		relativeFixups: list[tuple[int, int]] = []

		for i in range(methodListDef.count):
			methodAddr = (
				methodListAddr
				+ objc_method_list_t.SIZE
				+ (i * entsize)
			)

			if usesRelativeMethods:
				methodDef = self._slider.slideStruct(methodAddr, objc_method_small_t)
				methodOff = objc_method_list_t.SIZE + (i * entsize)

				if methodDef.name:
					nameAddr = methodAddr + methodDef.name
					newNameAddr = self._processString(nameAddr)
					methodDef.name = newNameAddr - methodAddr

					relativeFixups.append((methodOff, newNameAddr))
					pass

				if methodDef.types:
					typesAddr = methodAddr + 4 + methodDef.types
					newTypesAddr = self._processString(typesAddr)
					methodDef.types = newTypesAddr - (methodAddr + 4)

					relativeFixups.append((methodOff + 4, newTypesAddr))
					pass

				if noImp:
					methodDef.imp = 0
					pass

				methodListData.extend(methodDef)
				pass

			else:
				methodDef = self._slider.slideStruct(methodAddr, objc_method_large_t)

				if methodDef.name:
					methodDef.name = self._processString(methodDef.name)
					pass

				if methodDef.types:
					methodDef.types = self._processString(methodDef.types)
					pass

				if noImp:
					methodDef.imp = 0
					pass

				methodListData.extend(methodDef)
				pass
			pass

		# add or update data
		if self._machoCtx.containsAddr(methodListAddr):
			newMethodListAddr = methodListAddr

			defOff = self._dyldCtx.convertAddr(methodListAddr)
			self._machoCtx.writeBytes(defOff, methodListData)
			pass
		else:
			newMethodListAddr = self._extraDataHead

			# fix relative offsets now that we changed the address
			for fieldOff, fieldTarget in relativeFixups:
				newValue = fieldTarget - (newMethodListAddr + fieldOff)
				struct.pack_into("<i", methodListData, fieldOff, newValue)
				pass

			self._addExtraData(methodListData)
			pass

		self._methodListCache[methodListAddr] = newMethodListAddr
		return newMethodListAddr

	def _processString(self, stringAddr: int) -> int:
		if stringAddr in self._stringCache:
			return self._stringCache[stringAddr]

		# add or update data
		if self._machoCtx.containsAddr(stringAddr):
			newStringAddr = stringAddr
			pass
		else:
			newStringAddr = self._extraDataHead

			stringData = self._dyldCtx.readString(self._dyldCtx.convertAddr(stringAddr))
			self._addExtraData(stringData)
			pass

		self._stringCache[stringAddr] = newStringAddr
		return newStringAddr

	def _processInt(self, intAddr: int, intSize: int) -> int:
		if intAddr in self._intCache:
			return self._intCache[intAddr]

		if self._machoCtx.containsAddr(intAddr):
			newIntAddr = intAddr
			pass
		else:
			newIntAddr = self._extraDataHead

			intOff = self._dyldCtx.convertAddr(intAddr)
			intData = self._dyldCtx.getBytes(intOff, intSize)

			self._addExtraData(intData)
			pass

		self._intCache[intAddr] = newIntAddr
		return newIntAddr

	def _finalizeFutureClasses(self) -> None:
		extraSegStart = self._extraDataHead - len(self._extraData)

		while len(self._futureClasses):
			futureClass = self._futureClasses.pop()

			newAddr, needsFuture = self._processClass(futureClass[1])
			if needsFuture:
				self._logger.error(f"Unable to resolve class pointer at {hex(futureClass[0])}")  # noqa
				continue

			destPtr = futureClass[0]
			if destPtr >= extraSegStart and destPtr < self._extraDataHead:
				ptrOffset = destPtr - extraSegStart
				struct.pack_into("<Q", self._extraData, ptrOffset, newAddr)
				pass
			else:
				ptrOffset = self._dyldCtx.convertAddr(destPtr)
				struct.pack_into("Q", self._machoCtx.file, ptrOffset, newAddr)
				pass
			pass
		pass

	def _fixSelectors(self) -> None:
		"""Undo direct selector loading.

		Changes instructions to use the selref section again.
		"""

		try:
			textSect = self._machoCtx.segments[b"__TEXT"].sects[b"__text"]
			pass
		except KeyError:
			self._logger.error("Unable to get __text section")
			pass

		self._statusBar.update(status="Fixing Selectors")

		textSectAddr = textSect.addr
		textSectOff = self._dyldCtx.convertAddr(textSectAddr)

		for sectOff in range(0, textSect.size - 4, 4):
			# Direct selector loads consist of an ADRP and ADD instruction
			adrpOff = textSectOff + sectOff
			if self._machoCtx.file[adrpOff + 3] & 0x9F != 0x90:
				continue

			addOff = textSectOff + sectOff + 4
			if self._machoCtx.file[addOff + 3] != 0x91:
				continue

			adrp, add = self._machoCtx.readFormat(adrpOff, "<II")

			# verify that the ADRP Destination register matches
			# the ADD Base register
			adrpDestReg = adrp & 0x1F
			addBaseReg = (add >> 5) & 0x1F
			if adrpDestReg != addBaseReg:
				continue

			# get the selector address
			adrpAddr = textSectAddr + sectOff

			# ADRP
			immlo = (adrp & 0x60000000) >> 29
			immhi = (adrp & 0xFFFFE0) >> 3
			imm = (immhi | immlo) << 12
			imm = stub_fixer.Arm64Utilities.signExtend(imm, 33)

			adrpResult = (adrpAddr & ~0xFFF) + imm

			# ADD
			imm = (add & 0x3FFC00) >> 10
			loadTarget = adrpResult + imm

			if self._machoCtx.containsAddr(loadTarget):
				continue

			if loadTarget not in self._selRefCache:
				# There are some files that access strings that do not have
				# a selector reference. Pull in the string and repoint the
				# ADRP and ADD to it.
				stringAddr = self._processString(loadTarget)

				adrpDelta = (stringAddr & -4096) - (adrpAddr & -4096)
				immhi = (adrpDelta >> 9) & (0x00FFFFE0)
				immlo = (adrpDelta << 17) & (0x60000000)
				newAdrp = (0x90000000) | immlo | immhi | adrpDestReg

				addOff = stringAddr - (stringAddr & -4096)
				imm12 = (addOff << 10) & 0x3FFC00
				addDestReg = add & 0x1F
				newAdd = 0x91000000 | imm12 | (addBaseReg << 5) | addDestReg

				instructions = struct.pack("<II", newAdrp, newAdd)
				self._machoCtx.writeBytes(adrpOff, instructions)

				self._statusBar.update(status="Fixing Selectors")
				continue

			selRefPtr = self._selRefCache[loadTarget]

			# make new adrp and ldr instructions
			adrpDelta = (selRefPtr & -4096) - (adrpAddr & -4096)
			immhi = (adrpDelta >> 9) & (0x00FFFFE0)
			immlo = (adrpDelta << 17) & (0x60000000)
			newAdrp = 0x90000000 | immlo | immhi | adrpDestReg

			ldrOffset = selRefPtr - (selRefPtr & -4096)
			imm12 = (ldrOffset << 7) & 0x3FFC00
			ldrDestReg = add & 0x1F
			newLdr = 0xF9400000 | imm12 | (addBaseReg << 5) | ldrDestReg

			# write to new instructions
			instructions = struct.pack("<II", newAdrp, newLdr)
			self._machoCtx.writeBytes(adrpOff, instructions)

			self._statusBar.update(status="Fixing Selectors")
			pass
		pass

	def _checkSpaceConstraints(self) -> None:
		"""Check if we have enough space to add the new segment.
		"""

		# Check header
		headerEnd = (
			self._machoCtx.segmentsI[0].seg.vmaddr
			+ self._machoCtx.header.sizeofcmds
			+ mach_header_64.SIZE
		)
		textSectStart = self._machoCtx.segments[b"__TEXT"].sects[b"__text"].addr

		if (headerEnd + segment_command_64.SIZE) > textSectStart:
			spaceNeeded = (headerEnd + segment_command_64.SIZE) - textSectStart
			self._makeHeaderSpace(spaceNeeded)
			pass

		# Check data space
		if len(self._extraData) > self._extraDataMaxSize:
			raise _ObjCFixerError("Not enough space to add ObjC data.")
		pass

	def _makeHeaderSpace(self, spaceNeeded: int) -> None:
		"""Attempt to make more space in the header.
		"""

		bytesSaved = 0
		commandsToRemove = []

		# LC_UUID
		self._logger.info("Not enough header space, removing UUID command.")
		if uuidCmd := self._machoCtx.getLoadCommand((LoadCommands.LC_UUID,)):
			commandsToRemove.append(uuidCmd)
			bytesSaved += uuidCmd.cmdsize
			pass

		if bytesSaved < spaceNeeded:
			# empty linkedit data commands
			self._logger.warning("Not enough header space, removing empty linkedit data commands")  # noqa
			for cmd in self._machoCtx.loadCommands:
				if isinstance(cmd, linkedit_data_command):
					if cmd.datasize == 0:
						commandsToRemove.append(cmd)
						bytesSaved += cmd.cmdsize

						if bytesSaved >= spaceNeeded:
							break
						pass
					pass
				pass
			pass

		if bytesSaved < spaceNeeded:
			raise _ObjCFixerError("Unable to make enough room for extra ObjC segment command.")  # noqa

		# remake the header
		loadCommandsData = bytearray()
		readHead = self._machoCtx.fileOffset + mach_header_64.SIZE
		for i in range(self._machoCtx.header.ncmds):
			cmd = self._machoCtx.loadCommands[i]
			if cmd in commandsToRemove:
				continue

			loadCommandsData.extend(self._machoCtx.getBytes(readHead, cmd.cmdsize))
			readHead += cmd.cmdsize
			pass

		self._machoCtx.header.ncmds -= len(commandsToRemove)
		self._machoCtx.header.sizeofcmds = len(loadCommandsData)
		self._machoCtx.writeBytes(
			self._machoCtx.fileOffset + mach_header_64.SIZE,
			loadCommandsData
		)

		self._machoCtx = MachOContext(self._machoCtx.file, self._machoCtx.fileOffset)
		self._extractionCtx.machoCtx = self._machoCtx
		pass

	def _addExtraDataSeg(self) -> None:
		# update the size on the new segment
		self._extraSegment.vmsize = len(self._extraData)
		self._extraSegment.filesize = len(self._extraData)

		# insert the segment command right before the linkedit
		moveStart = self._machoCtx.segments[b"__LINKEDIT"].seg._fileOff_
		bytesToMove = (
			self._machoCtx.fileOffset
			+ mach_header_64.SIZE
			+ self._machoCtx.header.sizeofcmds
			- moveStart
		)
		self._machoCtx.file.move(
			moveStart + segment_command_64.SIZE,
			moveStart,
			bytesToMove
		)

		# add the new data and the segment command
		self._machoCtx.writeBytes(self._extraSegment.fileoff, self._extraData)
		self._machoCtx.writeBytes(moveStart, self._extraSegment)

		# update the header
		self._machoCtx.header.ncmds += 1
		self._machoCtx.header.sizeofcmds += segment_command_64.SIZE

		# recreate the macho context to reflect the new segment
		self._extractionCtx.machoCtx = MachOContext(
			self._machoCtx.file,
			self._machoCtx.fileOffset
		)
		pass
	pass


def fixObjC(extractionCtx: ExtractionContext) -> None:
	try:
		extractionCtx.statusBar.update(unit="ObjC Fixer")
		_ObjCFixer(extractionCtx).run()
		pass
	except _ObjCFixerError as e:
		extractionCtx.logger.error(f"Unable to fix ObjC, reason: {e}")
		pass
	pass
