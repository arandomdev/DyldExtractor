import struct
import copy

from typing import Tuple, List

from DyldExtractor import MachO, ObjC, Dyld


class ObjCConverterUnknownError(Exception):
	pass


class DynPtr(object):
	"""
		Tracks the location of a pointer within a section.
	"""

	def __init__(self, sourceSection: MachO.section_64, sourceOffset: int, targetSection: MachO.section_64, targetOffset: int) -> None:
		self.sourceSection = sourceSection
		self.sourceOffset = sourceOffset
		self.targetSection = targetSection
		self.targetOffset = targetOffset
	
	def finalize(self):
		pointer = struct.pack("<Q", self.targetSection.addr + self.targetOffset)
		
		newData = self.sourceSection.sectionData[0:self.sourceOffset]
		newData += pointer
		newData += self.sourceSection.sectionData[self.sourceOffset+8:]
		self.sourceSection.sectionData = newData


class ObjCConverter(object):
	"""
		Fixes objc data.
	"""

	def __init__(self, machoFile: MachO.MachoFile, dyldFile: Dyld.DyldFile) -> None:
		self.machoFile = machoFile
		self.dyldFile = dyldFile

		self.extraSegments: List[MachO.segment_command_64] = []
		self.ptrs = []
	
	def convert(self) -> None:
		for seg in self.machoFile.getLoadCommand(MachO.LoadCommands.LC_SEGMENT_64, multiple=True):
			# Skip libobjc.A.dylib
			if b"__OBJC_RW\x00" in seg.segname:
				print("\tSkip libobjc")
				return
			
			# Skip Swift dylibs
			for sect in seg.sections:
				if b"swift" in sect.sectname:
					print("\tSkip Swift")
					return

		self.processSegments()

		self.updateExtraSizes()

		for ptr in self.ptrs:
			ptr.finalize()

		# add the extra segments and update the header
		for i in range(0, len(self.machoFile.loadCommands)):
			loadCommand = self.machoFile.loadCommands[i]
			if loadCommand.cmd == MachO.LoadCommands.LC_SEGMENT_64 and b"__LINKEDIT" in loadCommand.segname:
				self.machoFile.loadCommands[i:i] = self.extraSegments
				break

		self.machoFile.machHeader.ncmds = len(self.machoFile.loadCommands)
		self.machoFile.machHeader.sizeofcmds += sum([segment.cmdsize for segment in self.extraSegments])
	
	def processSegments(self) -> None:
		segments: List[MachO.segment_command_64] = self.machoFile.getLoadCommand(MachO.LoadCommands.LC_SEGMENT_64, multiple=True)

		# Segments we need to zero out a byte on
		zero_segments = [b"classrefs", b"superrefs", b"protorefs", b"objc_data"]

		for segment in segments:
			for section in segment.sections:
				if not isinstance(section.sectionData, bytearray):
					section.sectionData = bytearray(section.sectionData)

				if any(x in section.sectname for x in zero_segments):
					if section.size > 16:
						for i in range(0, section.size, 8):
							selref = struct.unpack_from("<Q", section.sectionData, i)[0]
							selref &= 0xFFFFFFFFFF
							self.overwriteSectData(section, i, selref.to_bytes(8, 'little'))


				if b"__objc_selrefs\x00" in section.sectname:
					origSeg = self.machoFile.getSegment(b"__TEXT\x00", b"__objc_methname\x00")
					methSect = self.getExtraSection(origSeg[0], origSeg[1])

					for i in range(0, section.size, 8):
						selref = struct.unpack_from("<Q", section.sectionData, i)[0]
						selref &= 0xffffffffff
						
						if not self.machoFile.containsAddr(selref):
							method = self.dyldFile.readString(self.dyldFile.convertAddr(selref))

							methodOff = None
							if method in methSect.sectionData:
								methodOff = methSect.sectionData.index(method)
							else:
								methodOff = len(methSect.sectionData)
								methSect.sectionData += method

							self.ptrs.append(DynPtr(section, i, methSect, methodOff))
						else:
							struct.pack_into("<Q", section.sectionData, i, selref)
				
				elif b"__objc_classlist" in section.sectname:
					for i in range(0, section.size, 8):
						# process the class data
						classObjPtr = struct.unpack_from("<Q", section.sectionData, i)[0]
						classObjPtr &= 0xffffffffff
						struct.pack_into("<Q", section.sectionData, i, classObjPtr)

						classObjOff = self.dyldFile.convertAddr(classObjPtr)
						if classObjOff < 0:
							# will crash the program
							print(f'fail on {struct.unpack_from("<Q", section.sectionData, i)[0]}')
							continue
						classObj = ObjC.class_t.parse(self.dyldFile.file, classObjOff)


						classObj.isa &= 0xffffffffff
						classObj.superClass &= 0xffffffffff
						classObj.cache &= 0xffffffffff
						classObj.vtable &= 0xffffffffff
						classObj.data &= 0xffffffffff

						self.processClassData(classObj.data)

						# process metaclass data
						metaClsObjOff = self.dyldFile.convertAddr(classObj.isa)
						metaCls = ObjC.class_t.parse(self.dyldFile.file, metaClsObjOff)

						metaCls.isa &= 0xffffffffff
						metaCls.superClass &= 0xffffffffff
						metaCls.cache &= 0xffffffffff
						metaCls.vtable &= 0xffffffffff
						metaCls.data &= 0xffffffffff

						self.processClassData(metaCls.data)
				
				elif b"__objc_protolist" in section.sectname:
					for i in range(0, section.size, 8):
						protoPtr = struct.unpack_from("<Q", section.sectionData, i)[0]
						protoPtr &= 0xffffffffff
						if protoPtr <= 0:
							print(f'fail on {struct.unpack_from("<Q", section.sectionData, i)[0]}')
							continue
						protoSect, protoSectOff = self.processProtocolData(protoPtr)
						self.ptrs.append(DynPtr(section, i, protoSect, protoSectOff))
				
				elif b"__objc_catlist\x00" in section.sectname:
					for i in range(0, section.size, 8):
						catPtr = struct.unpack_from("<Q", section.sectionData, i)[0]
						catPtr &= 0xffffffffff
						if catPtr <= 0:
							print(f'fail on {struct.unpack_from("<Q", section.sectionData, i)[0]}')
							continue
						catSect, catSectOff = self.processCategory(catPtr)
						self.ptrs.append(DynPtr(section, i, catSect, catSectOff))
	
	def processClassData(self, classDataPtr: int) -> None:
		"""
			Processes a class_rw_t.
		"""

		classDataOff = self.dyldFile.convertAddr(classDataPtr)
		classData = ObjC.class_rw_t.parse(self.dyldFile.file, classDataOff)

		classData.name &= 0xffffffffff
		classData.baseMethods &= 0xffffffffff
		classData.baseProtocols &= 0xffffffffff
		classData.ivars &= 0xffffffffff
		classData.baseProperties &= 0xffffffffff
		
		classDataSect = None
		classDataSectOff = None

		if self.machoFile.containsAddr(classDataPtr):
			classDataSect = self.machoFile.segmentForAddr(classDataPtr)[1]
			classDataSectOff = classDataPtr - classDataSect.addr
		else:	raise ObjCConverterUnknownError

		# pull in extra data
		if not self.machoFile.containsAddr(classData.name):
			origSeg = self.machoFile.getSegment(b"__TEXT\x00", b"__objc_classname")
			classNameSect = self.getExtraSection(origSeg[0], origSeg[1])

			name = self.dyldFile.readString(self.dyldFile.convertAddr(classData.name))
			nameOff = None

			if name in classNameSect.sectionData:
				nameOff = classNameSect.sectionData.index(name)
			else:
				nameOff = len(classNameSect.sectionData)
				classNameSect.sectionData += name

			nameFieldOff = classDataSectOff+classData.offsetOf("name")
			self.ptrs.append(DynPtr(classDataSect, nameFieldOff, classNameSect, nameOff))
		
		if classData.baseMethods:
			if not self.machoFile.containsAddr(classData.baseMethods):	print("basemethods") # TODO: remove
			self.processMethodList(classData.baseMethods)
		
		if classData.baseProtocols:
			if not self.machoFile.containsAddr(classData.baseProtocols):	print("baseProtocols") # TODO: remove
			self.processProtocolList(classData.baseProtocols)

		if classData.ivars:
			if not self.machoFile.containsAddr(classData.ivars):	print("ivars") # TODO: remove
			self.processIvarList(classData.ivars)

		if classData.baseProperties:
			if not self.machoFile.containsAddr(classData.baseProperties):	print("baseProperties") # TODO: remove
			self.processPropertyList(classData.baseProperties)

	def processMethodList(self, methListPtr: int) -> Tuple[MachO.section_64, int]:
		"""
			Processes a method_list_t along with its method_t.

			returns a tuple with the containing section as well
			as its offset in the section.
		"""
		methListOff = self.dyldFile.convertAddr(methListPtr)
		methList = ObjC.method_list_t.parse(self.dyldFile.file, methListOff)

		methListSect = None
		methListSectOff = None

		methListData = methList.asBytes()
		for meth in methList.methods:
			meth.name &= 0xffffffffff
			meth.type &= 0xffffffffff
			meth.imp &= 0xffffffffff
			methListData += meth.asBytes()

		if self.machoFile.containsAddr(methListPtr):
			methListSect = self.machoFile.segmentForAddr(methListPtr)[1]
			methListSectOff = methListPtr - methListSect.addr

			self.overwriteSectData(methListSect, methListSectOff, methListData)
		else:
			origSeg = self.machoFile.getSegment(b"__DATA_CONST\x00", b"__objc_const\x00")
			methListSect = self.getExtraSection(origSeg[0], origSeg[1])

			# check if it's already decached
			if methListData in methListSect.sectionData:
				methListSectOff = methListSect.sectionData.index(methListData)
			else:
				methListSectOff = len(methListSect.sectionData)
				methListSect.sectionData += methListData
		
		# pull in method_t data
		for meth in methList.methods:
			if not self.machoFile.containsAddr(meth.name):
				origSeg = self.machoFile.getSegment(b"__TEXT\x00", b"__objc_methname\x00")
				methnameSect = self.getExtraSection(origSeg[0], origSeg[1])

				name = self.dyldFile.readString(self.dyldFile.convertAddr(meth.name))
				nameOff = None

				if name in methnameSect.sectionData:
					nameOff = methnameSect.sectionData.index(name)
				else:
					nameOff = len(methnameSect.sectionData)
					methnameSect.sectionData += name
				
				nameFieldOff = methListSectOff + methList.SIZE + (methList.methods.index(meth) * meth.SIZE)
				self.ptrs.append(DynPtr(methListSect, nameFieldOff, methnameSect, nameOff))
			
			if not self.machoFile.containsAddr(meth.type):
				origSeg = self.machoFile.getSegment(b"__TEXT\x00", b"__objc_methtype\x00")
				methtypeSect = self.getExtraSection(origSeg[0], origSeg[1])

				methtype = self.dyldFile.readString(self.dyldFile.convertAddr(meth.type))
				methtypeOff = None

				if methtype in methtypeSect.sectionData:
					methtypeOff = methtypeSect.sectionData.index(methtype)
				else:
					methtypeOff = len(methtypeSect.sectionData)
					methtypeSect.sectionData += methtype
				
				methtypeFieldOff = methListSectOff + methList.SIZE + (methList.methods.index(meth) * meth.SIZE) + meth.offsetOf("type")
				self.ptrs.append(DynPtr(methListSect, methtypeFieldOff, methtypeSect, methtypeOff))
			
			if meth.imp and not self.machoFile.containsAddr(meth.imp):
				pass
				# print("Could not find method imp: " + str(meth.imp))
				# raise ObjCConverterUnknownError
		
		return methListSect, methListSectOff
	
	def processProtocolList(self, protoListPtr: int) -> Tuple[MachO.section_64, int]:
		protoListOff = self.dyldFile.convertAddr(protoListPtr)
		protoList = ObjC.protocol_list_t.parse(self.dyldFile.file, protoListOff)

		protoListSect = None
		protoListSectOff = None

		if self.machoFile.containsAddr(protoListPtr):
			protoListSect = self.machoFile.segmentForAddr(protoListPtr)[1]
			protoListSectOff = protoListPtr - protoListSect.addr
		else:
			origSeg = self.machoFile.getSegment(b"__DATA_CONST\x00", b"__objc_const\x00")
			protoListSect = self.getExtraSection(origSeg[0], origSeg[1])

			protoListData = protoList.asBytes() + protoList.protocolPtrs
			if protoListData in protoListSect.sectionData:
				protoListSectOff = protoListSect.sectionData.index(protoListData)
			else:
				protoListSectOff = len(protoListSect.sectionData)
				protoListSect.sectionData += protoListData
		
		for i in range(0, len(protoList.protocolPtrs), 8):
			protoPtr = struct.unpack_from("<Q", protoList.protocolPtrs, i)[0]
			protoPtr &= 0xffffffffff

			protoDataSect, protoDataSectOff = self.processProtocolData(protoPtr)
			protoFieldOff = protoListSectOff + protoList.SIZE + i

			self.ptrs.append(DynPtr(protoListSect, protoFieldOff, protoDataSect, protoDataSectOff))
		
		return protoListSect, protoListSectOff
	
	def processProtocolData(self, protoDataPtr: int) -> Tuple[MachO.section_64, int]:
		protoDataOff = self.dyldFile.convertAddr(protoDataPtr)
		protoData = ObjC.protocol_t.parse(self.dyldFile.file, protoDataOff)

		protoData.isa = 0
		protoData.name &= 0xffffffffff
		protoData.protocols &= 0xffffffffff
		protoData.instanceMethods &= 0xffffffffff
		protoData.classMethods &= 0xffffffffff
		protoData.optionalInstanceMethods &= 0xffffffffff
		protoData.optionalClassMethods &= 0xffffffffff
		protoData.instanceProperties &= 0xffffffffff

		protoDataSect = None
		protoDataSectOff = None

		protoDataBytes = protoData.asBytes()

		if self.machoFile.containsAddr(protoDataPtr):
			protoDataSect = self.machoFile.segmentForAddr(protoDataPtr)[1]
			protoDataSectOff = protoDataPtr - protoDataSect.addr

			self.overwriteSectData(protoDataSect, protoDataSectOff, protoDataBytes)
		else:
			origSeg = self.machoFile.getSegment(b"__DATA\x00", b"__data\x00")
			protoDataSect = self.getExtraSection(origSeg[0], origSeg[1])

			if protoDataBytes in protoDataSect.sectionData:
				protoDataSectOff = protoDataSect.sectionData.index(protoDataBytes)
			else:
				protoDataSectOff = len(protoDataSect.sectionData)
				protoDataSect.sectionData += protoDataBytes
		
		if not self.machoFile.containsAddr(protoData.name):
			origSeg = self.machoFile.getSegment(b"__TEXT\x00", b"__objc_classname")
			classnameSect = self.getExtraSection(origSeg[0], origSeg[1])

			name = self.dyldFile.readString(self.dyldFile.convertAddr(protoData.name))
			nameOff = None

			if name in classnameSect.sectionData:
				nameOff = classnameSect.sectionData.index(name)
			else:
				nameOff = len(classnameSect.sectionData)
				classnameSect.sectionData += name
			
			self.ptrs.append(DynPtr(protoDataSect, protoDataSectOff+protoData.offsetOf("name"), classnameSect, nameOff))
		
		if protoData.protocols:
			protoListSect, protoListSectOff = self.processProtocolList(protoData.protocols)
			protoListFieldOff = protoDataSectOff + protoData.offsetOf("protocols")
			self.ptrs.append(DynPtr(protoDataSect, protoListFieldOff, protoListSect, protoListSectOff))

		if protoData.instanceMethods:
			instMethSect, instMethSectOff = self.processMethodList(protoData.instanceMethods)
			instMethFieldOff = protoDataSectOff + protoData.offsetOf("instanceMethods")
			self.ptrs.append(DynPtr(protoDataSect, instMethFieldOff, instMethSect, instMethSectOff))

		if protoData.classMethods:
			clsMethSect, clsMethSectOff = self.processMethodList(protoData.classMethods)
			clsMethFieldOff = protoDataSectOff + protoData.offsetOf("classMethods")
			self.ptrs.append(DynPtr(protoDataSect, clsMethFieldOff, clsMethSect, clsMethSectOff))
		
		if protoData.optionalInstanceMethods:
			optInstMethSect, optInstMethSectOff = self.processMethodList(protoData.optionalInstanceMethods)
			optInstMethFieldOff = protoDataSectOff + protoData.offsetOf("optionalInstanceMethods")
			self.ptrs.append(DynPtr(protoDataSect, optInstMethFieldOff, optInstMethSect, optInstMethSectOff))

		if protoData.optionalClassMethods:
			optClsMethSect, optClsMethSectOff = self.processMethodList(protoData.optionalClassMethods)
			optClsMethFieldOff = protoDataSectOff + protoData.offsetOf("optionalClassMethods")
			self.ptrs.append(DynPtr(protoDataSect, optClsMethFieldOff, optClsMethSect, optClsMethSectOff))
		
		if protoData.instanceProperties:
			propSect, propSectOff = self.processPropertyList(protoData.instanceProperties)
			propFieldOff = protoDataSectOff + protoData.offsetOf("instanceProperties")
			self.ptrs.append(DynPtr(protoDataSect, propFieldOff, propSect, propSectOff))

		return protoDataSect, protoDataSectOff

	def processIvarList(self, ivarListPtr: int) -> None:
		ivarListOff = self.dyldFile.convertAddr(ivarListPtr)
		ivarList = ObjC.ivar_list_t.parse(self.dyldFile.file, ivarListOff)

		ivarListSect = None
		ivarListSectOff = None

		ivarListData = ivarList.asBytes()
		for ivar in ivarList.ivars:
			ivar.offset &= 0xffffffffff
			ivar.name &= 0xffffffffff
			ivar.type &= 0xffffffffff
			ivarListData += ivar.asBytes()
		
		if self.machoFile.containsAddr(ivarListPtr):
			ivarListSect = self.machoFile.segmentForAddr(ivarListPtr)[1]
			ivarListSectOff = ivarListPtr - ivarListSect.addr

			self.overwriteSectData(ivarListSect, ivarListSectOff, ivarListData)
		else:
			origSeg = self.machoFile.getSegment(b"__DATA_CONST\x00", b"__objc_const\x00")
			ivarListSect = self.getExtraSection(origSeg[0], origSeg[1])

			if ivarListData in ivarListSect.sectionData:
				ivarListSectOff = ivarListSect.sectionData.index(ivarListData)
			else:
				ivarListSectOff = len(ivarListSect.sectionData)
				ivarListSect.sectionData += ivarListData
		
		for ivar in ivarList.ivars:
			if not self.machoFile.containsAddr(ivar.offset):
				raise ObjCConverterUnknownError

			if not self.machoFile.containsAddr(ivar.name):
				origSeg = self.machoFile.getSegment(b"__TEXT\x00", b"__objc_methname\x00")
				methnameSect = self.getExtraSection(origSeg[0], origSeg[1])

				name = self.dyldFile.readString(self.dyldFile.convertAddr(ivar.name))
				nameOff = None

				if name in methnameSect.sectionData:
					nameOff = methnameSect.sectionData.index(name)
				else:
					nameOff = len(methnameSect.sectionData)
					methnameSect.sectionData += name
				
				nameFieldOff = ivarListSectOff + ivarList.SIZE + (ivarList.ivars.index(ivar) * ivar.SIZE) + ivar.offsetOf("name")
				self.ptrs.append(DynPtr(ivarListSect, nameFieldOff, methnameSect, nameOff))
			
			if not self.machoFile.containsAddr(ivar.type):
				origSeg = self.machoFile.getSegment(b"__TEXT\x00", b"__objc_methtype\x00")
				methtypeSect = self.getExtraSection(origSeg[0], origSeg[1])

				methtype = self.dyldFile.readString(self.dyldFile.convertAddr(ivar.type))
				methtypeOff = None

				if methtype in methtypeSect.sectionData:
					methtypeOff = methtypeSect.sectionData.index(methtype)
				else:
					methtypeOff = len(methtypeSect.sectionData)
					methtypeSect.sectionData += methtype
				
				methtypeFieldOff = ivarListSectOff + ivarList.SIZE + (ivarList.ivars.index(ivar) * ivar.SIZE) + ivar.offsetOf("type")
				self.ptrs.append(DynPtr(ivarListSect, methtypeFieldOff, methtypeSect, methtypeOff))

	def processPropertyList(self, propListPtr: int) -> Tuple[MachO.section_64, int]:
		propListOff = self.dyldFile.convertAddr(propListPtr)
		propList = ObjC.property_list_t.parse(self.dyldFile.file, propListOff)

		propListSect = None
		propListSectOff = None

		propListData = propList.asBytes()
		for prop in propList.properties:
			prop.name &= 0xffffffffff
			prop.attributes &= 0xffffffffff
			propListData += prop.asBytes()
		
		if self.machoFile.containsAddr(propListPtr):
			propListSect = self.machoFile.segmentForAddr(propListPtr)[1]
			propListSectOff = propListPtr - propListSect.addr

			self.overwriteSectData(propListSect, propListSectOff, propListData)
		else:
			origSeg = self.machoFile.getSegment(b"__DATA_CONST\x00", b"__objc_const\x00")
			propListSect = self.getExtraSection(origSeg[0], origSeg[1])

			if propListData in propListSect.sectionData:
				propListSectOff = propListSect.sectionData.index(propListData)
			else:
				propListSectOff = len(propListSect.sectionData)
				propListSect.sectionData += propListData
		
		for prop in propList.properties:
			if not self.machoFile.containsAddr(prop.name):
				origSeg = self.machoFile.getSegment(b"__TEXT\x00", b"__cstring\x00")
				cstringSect = self.getExtraSection(origSeg[0], origSeg[1])

				name = self.dyldFile.readString(self.dyldFile.convertAddr(prop.name))
				nameOff = None

				if name in cstringSect.sectionData:
					nameOff = cstringSect.sectionData.index(name)
				else:
					nameOff = len(cstringSect.sectionData)
					cstringSect.sectionData += name
				
				nameFieldOff = propListSectOff + propList.SIZE + (propList.properties.index(prop) * prop.SIZE)
				self.ptrs.append(DynPtr(propListSect, nameFieldOff, cstringSect, nameOff))
			
			if not self.machoFile.containsAddr(prop.attributes):
				origSeg = self.machoFile.getSegment(b"__TEXT\x00", b"__cstring\x00")
				cstringSect = self.getExtraSection(origSeg[0], origSeg[1])

				attr = self.dyldFile.readString(self.dyldFile.convertAddr(prop.attributes))
				attrOff = None

				if attr in cstringSect.sectionData:
					attrOff = cstringSect.sectionData.index(attr)
				else:
					attrOff = len(cstringSect.sectionData)
					cstringSect.sectionData += attr
				
				attrFieldOff = propListSectOff + propList.SIZE + (propList.properties.index(prop) * prop.SIZE) + prop.offsetOf("attributes")
				self.ptrs.append(DynPtr(propListSect, attrFieldOff, cstringSect, attrOff))

		return propListSect, propListSectOff

	def processCategory(self, catPtr: int) -> Tuple[MachO.section_64, int]:
		catOff = self.dyldFile.convertAddr(catPtr)
		cat = ObjC.category_t.parse(self.dyldFile.file, catOff)

		cat.name &= 0xffffffffff
		cat.classRef &= 0xffffffffff
		cat.instanceMethods &= 0xffffffffff
		cat.classMethods &= 0xffffffffff
		cat.protocols &= 0xffffffffff
		cat.instanceProperties &= 0xffffffffff
		cat.classProperties &= 0xffffffffff

		catSect = None
		catSectOff = None

		catData = cat.asBytes()

		if self.machoFile.containsAddr(catPtr):
			catSect = self.machoFile.segmentForAddr(catPtr)[1]
			catSectOff = catPtr - catSect.addr

			self.overwriteSectData(catSect, catSectOff, catData)
		else:
			origSeg = self.machoFile.getSegment(b"__DATA_CONST\x00", b"__objc_const\x00")
			catSect = self.getExtraSection(origSeg[0], origSeg[1])

			if catData in catSect.sectionData:
				catSectOff = catSect.sectionData.index(catData)
			else:
				catSectOff = len(catSect.sectionData)
				catSect.sectionData += catData
		
		if not self.machoFile.containsAddr(cat.name):
			origSeg = self.machoFile.getSegment(b"__TEXT\x00", b"__objc_classname")
			classnameSect = self.getExtraSection(origSeg[0], origSeg[1])

			name = self.dyldFile.readString(self.dyldFile.convertAddr(cat.name))
			nameOff = None

			if name in classnameSect.sectionData:
				nameOff = classnameSect.sectionData.index(name)
			else:
				nameOff = len(classnameSect.sectionData)
				classnameSect.sectionData += name
			
			self.ptrs.append(DynPtr(catSect, catSectOff+cat.offsetOf("name"), classnameSect, nameOff))
		
		# TODO: process classRef

		if cat.instanceMethods:
			instMethSect, instMethSectOff = self.processMethodList(cat.instanceMethods)
			instMethFieldOff = catSectOff + cat.offsetOf("instanceMethods")
			self.ptrs.append(DynPtr(catSect, instMethFieldOff, instMethSect, instMethSectOff))

		if cat.classMethods:
			clsMethSect, clsMethSectOff = self.processMethodList(cat.classMethods)
			clsMethFieldOff = catSectOff + cat.offsetOf("classMethods")
			self.ptrs.append(DynPtr(catSect, clsMethFieldOff, clsMethSect, clsMethSectOff))

		if cat.protocols:
			protoSect, protoSectOff = self.processProtocolList(cat.protocols)
			protoFieldOff = catSectOff + cat.offsetOf("protocols")
			self.ptrs.append(DynPtr(catSect, protoFieldOff, protoSect, protoSectOff))

		if cat.instanceProperties:
			instPropSect, instPropSectOff = self.processPropertyList(cat.instanceProperties)
			instPropFieldOff = catSectOff + cat.offsetOf("instanceProperties")
			self.ptrs.append(DynPtr(catSect, instPropFieldOff, instPropSect, instPropSectOff))

		if cat.classProperties:
			clsPropSect, clsPropSectOff = self.processPropertyList(cat.classProperties)
			clsPropFieldOff = catSectOff + cat.offsetOf("classProperties")
			self.ptrs.append(DynPtr(catSect, clsPropFieldOff, clsPropSect, clsPropSectOff))

		return catSect, catSectOff

	def overwriteSectData(self, section: MachO.section_64, offset: int, data: bytes) -> None:
		sectionData = section.sectionData[0:offset]
		sectionData += data
		sectionData += section.sectionData[offset+len(data):]
		section.sectionData = sectionData

	def getExtraSection(self, originalSegment: MachO.segment_command_64, originalSection: MachO.section_64) -> MachO.section_64:
		"""
			Obtains or creates an duplicated segment that can be used to
			add extra data. The section returned will have the same flags,
			name, and segment parent as the originals. Every pointer
			referencing these sections should be dynamic pointers as they
			are subject to moving.


			# Parameters
			originalSegment: segment_command_64

				The segment that is used to create a duplicate segment.
			originalSection: section_64

				The section that is used to create a duplicate section.


			# Return
			section_64
				The segment returned is either a newly duplicated section or an
				pre-existing section.
		"""

		# TODO: VMAddr does not need to be page aligned

		# Serves as the initial segment size and as the page size
		SEGMENT_SIZE = 0x4000
		
		# get or create the last matching segment
		dupSegment = None
		for segment in self.extraSegments:
			trueSegName = segment.segname[0:1] + b"_" + segment.segname[2:]
			if trueSegName in originalSegment.segname:
				dupSegment = segment
				break

		if not dupSegment:
			dupSegment = copy.deepcopy(originalSegment)

			# change the name of the segment, ex. _XTEXT\x00..., _XDATA\x00
			dupSegment.segname = dupSegment.segname[0:1] + b"X" + dupSegment.segname[2:]
			
			# clear the sections
			dupSegment.sections.clear()
			dupSegment.nsects = 0
			dupSegment.vmsize = 0
			dupSegment.filesize = 0

			# get the next avaliable, page aligned, memory space.
			if len(self.extraSegments):
				lastSegment = self.extraSegments[-1]
				newAddress = lastSegment.vmaddr + lastSegment.vmsize + SEGMENT_SIZE
				newAddress -= newAddress % SEGMENT_SIZE
				dupSegment.vmaddr = newAddress
			else:
				for i in range(0, len(self.machoFile.loadCommands)):
					loadCommand = self.machoFile.loadCommands[i]
					if loadCommand.cmd == MachO.LoadCommands.LC_SEGMENT_64 and b"__LINKEDIT" in loadCommand.segname:
						lastSegment = self.machoFile.loadCommands[i - 1]
						newAddress = lastSegment.vmaddr + lastSegment.vmsize + SEGMENT_SIZE
						newAddress -= newAddress % SEGMENT_SIZE
						dupSegment.vmaddr = newAddress
						break
			self.extraSegments.append(dupSegment)
		
		# get or create the last matching section
		for section in dupSegment.sections:
			trueSectName = section.sectname[0:1] + b"_" + section.sectname[2:]
			if trueSectName in originalSection.sectname:
				return section
		
		dupSection = copy.deepcopy(originalSection)
		
		# change the name of the section, ex. _Xtext\x00..., _Xobjc_methname
		dupSection.segname = dupSegment.segname
		dupSection.sectname = dupSection.sectname[0:1] + b"X" + dupSection.sectname[2:]

		# clear its data
		dupSection.sectionData = b""
		dupSection.size = 0
		
		# get the next available memory space
		if len(dupSegment.sections):
			lastSection = dupSegment.sections[-1]
			dupSection.addr = lastSection.addr + len(lastSection.sectionData)
		else:
			dupSection.addr = dupSegment.vmaddr
		dupSegment.sections.append(dupSection)
		dupSegment.nsects += 1

		return dupSection

	def updateExtraSizes(self):
		PAGE_SIZE = 0x4000

		if len(self.extraSegments) == 0:
			return

		segmentHead = self.extraSegments[0].vmaddr
		for segment in self.extraSegments:
			segment.vmaddr = segmentHead
			
			sectionHead = segmentHead
			for section in segment.sections:
				section.addr = sectionHead
				section.offset = sectionHead
				section.size = len(section.sectionData)
				sectionHead += section.size
			
			segment.cmdsize = segment.SIZE + (segment.nsects * MachO.section_64.SIZE)
			segment.vmsize = sectionHead - segment.vmaddr
			segment.filesize = sectionHead - segment.vmaddr

			while segmentHead < segment.vmsize:
				segmentHead += PAGE_SIZE