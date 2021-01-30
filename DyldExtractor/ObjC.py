from __future__ import annotations
from typing import ClassVar, List
from io import BufferedReader

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
		("offset", "<i")
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
		("entsizeAndFlags", "<I")
		("count", "<I")
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

	SIZE: ClassVar[int] = 24

	name: int
	type: int
	imp: int

	_fields_ = (
		("name", "<Q"),
		("type", "<Q"),
		("imp", "<Q"),
	)


class method_list_t(entsize_list_tt):

	SIZE: ClassVar[int] = 8

	entsize: int
	count: int

	methods: List[method_t]

	_fields_ = (
		("entsize", "<I"),
		("count", "<I"),
	)

	@classmethod
	def parse(cls, buffer: BufferedReader, fileOffset: int, loadData: bool = True) -> method_list_t:
		inst = super().parse(buffer, fileOffset, method_t, 0xffff0003, loadData=loadData)

		inst.methods = []
		for i in range(0, inst.count):
			methodOff = fileOffset + inst.SIZE + (i * method_t.SIZE)
			inst.methods.append(method_t.parse(buffer, methodOff, loadData=loadData))
		return inst


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