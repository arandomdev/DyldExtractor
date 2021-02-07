from __future__ import annotations
from typing import ClassVar, List, Union
from io import BufferedReader

import struct

from DyldExtractor.Structure import Structure


class class_t(Structure):
	
	SIZE: ClassVar[int] = 40

	isa: int 			# pointer to class_t
	superClass: int 	# pointer to class_t
	cache: int
	vtable: int
	data: int 			# pointer to class_rw_t

	_fields_ = (
		("isa", "<Q"),
		("superClass", "<Q"),
		("cache", "<Q"),
		("vtable", "<Q"),
		("data", "<Q"),
	)


class class_rw_t(Structure):
	
	SIZE: ClassVar[int] = 72

	flags: int
	instanceStart: int
	instanceSize: int
	name: int 			# char *
	baseMethods: int 	# method_list_t *
	baseProtocols: int 	# protocol_list_t *
	ivars: int 			# ivar_list_t *
	weakIvarLayout: int
	baseProperties: int # objc_property_list *

	_fields_ = (
		("flags", "<Q"),
		("instanceStart", "<Q"),
		("instanceSize", "<Q"),
		("name", "<Q"),
		("baseMethods", "<Q"),
		("baseProtocols", "<Q"),
		("ivars", "<Q"),
		("weakIvarLayout", "<Q"),
		("baseProperties", "<Q"),
	)


class RelativePointer(Structure):

	offset: int

	_fields_ = (
		("offset", "<i"),
	)

	@classmethod
	def parse(cls, buffer: BufferedReader, offset: int, vmAddr: int, loadData: bool) -> Structure:
		inst = super().parse(buffer, offset, loadData=loadData)

		inst.vmAddr = vmAddr
		return inst

	def getP(self):
		"""Return the pointer.
		"""

		if self.offset == 0:
			return 0

		return self.vmAddr + self.offset


class entsize_list_tt(Structure):

	entsizeAndFlags: int
	count: int

	elementList: List[Structure]

	_fields_ = (
		("entsizeAndFlags", "<I"),
		("count", "<I"),
	)

	@classmethod
	def parse(cls, buffer: BufferedReader, fileOffset: int, element: Structure, flagMask: int, loadData: bool=True):
		inst = super().parse(buffer, fileOffset, loadData=loadData)

		inst.elementType = element
		inst.flagmask = flagMask

		return inst

	def entsize(self):
		return self.entsizeAndFlags & ~self.flagmask
	
	def flags(self):
		return self.entsizeAndFlags & self.flagmask


class method_t(Structure):

	smallMethodListFlag = 0x80000000
	isSmall: bool
	size: int

	name: Union[int, RelativePointer]
	type: Union[int, RelativePointer]
	imp: Union[int, RelativePointer]

	_fields_ = ()

	@classmethod
	def parse(cls, buffer: BufferedReader, offset: int, vmAddr: int, isSmall: bool=False, loadData: bool=True) -> method_t:
		inst = super().parse(buffer, offset, loadData=loadData)

		inst.isSmall = isSmall

		inst.size = 12 if inst.isSmall else 24

		if inst.isSmall:
			inst.name = RelativePointer.parse(buffer, offset, vmAddr, loadData=loadData)
			inst.type = RelativePointer.parse(buffer, offset + 4, vmAddr + 4, loadData=loadData)
			inst.imp = RelativePointer.parse(buffer, offset + 8, vmAddr + 8, loadData=loadData)
		else:
			buffer.seek(offset)
			data = buffer.read(24)
			inst.name = struct.unpack_from("<Q", data, 0)[0]
			inst.type = struct.unpack_from("<Q", data, 8)[0]
			inst.imp = struct.unpack_from("<Q", data, 16)[0]

		return inst
	
	def asBytes(self) -> bytes:
		data = super().asBytes()

		if self.isSmall:
			data += self.name.asBytes()
			data += self.type.asBytes()
			data += self.imp.asBytes()
		else:
			data += struct.pack("<Q", self.name)
			data += struct.pack("<Q", self.type)
			data += struct.pack("<Q", self.imp)

		return data
	
	def offsetOf(self, field) -> int:
		if field == "name":
			return 0
		elif field == "type":
			return 4 if self.isSmall else 8
		elif field == "imp":
			return 8 if self.isSmall else 16


class method_list_t(entsize_list_tt):

	SIZE: ClassVar[int] = 8

	methods: List[method_t]

	_fields_ = (

	)

	@classmethod
	def parse(cls, buffer: BufferedReader, fileOffset: int, vmAddr: int, loadData: bool = True) -> method_list_t:
		inst = super().parse(buffer, fileOffset, method_t, 0xffff0003, loadData=loadData)

		isSmallList = inst.isSmallList()
		methodSize = 12 if isSmallList else 24
		inst.methods = []
		for i in range(0, inst.count):
			methodOff = fileOffset + inst.SIZE + (i * methodSize)
			methAddr = vmAddr + inst.SIZE + (i * methodSize)
			inst.methods.append(method_t.parse(buffer, methodOff, methAddr, isSmall=isSmallList, loadData=loadData))
		
		return inst
	
	def isSmallList(self):
		return self.entsizeAndFlags & method_t.smallMethodListFlag


class protocol_t(Structure):

	isa: int
	name: int
	protocols: int
	instanceMethods: int
	classMethods: int
	optionalInstanceMethods: int
	optionalClassMethods: int
	instanceProperties: int
	size: int
	flags: int

	_fields_ = (
		("isa", "<Q"),
		("name", "<Q"),
		("protocols", "<Q"),
		("instanceMethods", "<Q"),
		("classMethods", "<Q"),
		("optionalInstanceMethods", "<Q"),
		("optionalClassMethods", "<Q"),
		("instanceProperties", "<Q"),
		("size", "<I"),
		("flags", "<I"),
	)


class protocol_list_t(Structure):

	SIZE: ClassVar[int] = 8

	count: int

	protocolPtrs: bytes

	_fields_ = (
		("count", "<Q"),
	)

	def loadData(self) -> None:
		self._buffer.seek(self.SIZE + self._offset)
		self.protocolPtrs = self._buffer.read(8 * self.count)


class ivar_t(Structure):

	SIZE: ClassVar[int] = 32

	offset: int
	name: int
	type: int
	alignment: int
	size: int

	_fields_ = (
		("offset", "<Q"),
		("name", "<Q"),
		("type", "<Q"),
		("alignment", "<I"),
		("size", "<I"),
	)


class ivar_list_t(Structure):

	SIZE: ClassVar[int] = 8

	entsize: int
	count: int

	ivars: List[ivar_t]

	_fields_ = (
		("entsize", "<I"),
		("count", "<I"),
	)

	@classmethod
	def parse(cls, buffer: BufferedReader, fileOffset: int, loadData: bool = True) -> ivar_list_t:
		inst = super().parse(buffer, fileOffset, loadData=loadData)

		inst.ivars = []
		for i in range(0, inst.count):
			ivarOff = fileOffset + inst.SIZE + (i * ivar_t.SIZE)
			inst.ivars.append(ivar_t.parse(buffer, ivarOff, loadData=loadData))
		return inst


class property_t(Structure):

	SIZE: ClassVar[int] = 16

	name: int
	attributes: int

	_fields_ = (
		("name", "<Q"),
		("attributes", "<Q"),
	)


class property_list_t(Structure):

	SIZE: ClassVar[int] = 8

	entsize: int
	count: int

	properties: List[property_t]

	_fields_ = (
		("entsize", "<I"),
		("count", "<I"),
	)

	@classmethod
	def parse(cls, buffer: BufferedReader, fileOffset: int, loadData: bool = True) -> property_list_t:
		inst = super().parse(buffer, fileOffset, loadData=loadData)

		inst.properties = []
		for i in range(0, inst.count):
			propertyOff = fileOffset + inst.SIZE + (i * property_t.SIZE)
			inst.properties.append(property_t.parse(buffer, propertyOff, loadData=loadData))
		return inst


class category_t(Structure):

	name: int 				# char *
	classRef: int 			# class_t *
	instanceMethods: int 	# method_list_t *
	classMethods: int 		# method_list_t *
	protocols: int 			# protocol_list_t *
	instanceProperties: int # property_list_t *
	classProperties: int 	# property_list_t *

	_fields_ = (
		("name", "<Q"),
		("classRef", "<Q"),
		("instanceMethods", "<Q"),
		("classMethods", "<Q"),
		("protocols", "<Q"),
		("instanceProperties", "<Q"),
		("classProperties", "<Q"),
	)