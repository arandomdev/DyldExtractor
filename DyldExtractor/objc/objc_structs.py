from ctypes import (
	c_int32,
	c_uint32,
	c_uint64
)
from os import name

from DyldExtractor.structure import Structure


class objc_class_t(Structure):

	isa: int
	superclass: int
	method_cache: int
	vtable: int
	data: int

	_fields_ = [
		("isa", c_uint64),
		("superclass", c_uint64),
		("method_cache", c_uint64),
		("vtable", c_uint64),
		("data", c_uint64),
	]

	_pointers_ = [
		"isa",
		"superclass",
		"method_cache",
		"vtable",
		"data",
	]


class objc_class_data_t(Structure):

	flags: int
	instanceStart: int
	instanceSize: int
	pad: int
	ivarLayout: int
	name: int
	baseMethods: int
	baseProtocols: int
	ivars: int
	weakIvarLayout: int
	baseProperties: int

	_fields_ = [
		("flags", c_uint32),
		("instanceStart", c_uint32),
		("instanceSize", c_uint32),
		("pad", c_uint32),
		("ivarLayout", c_uint64),
		("name", c_uint64),
		("baseMethods", c_uint64),
		("baseProtocols", c_uint64),
		("ivars", c_uint64),
		("weakIvarLayout", c_uint64),
		("baseProperties", c_uint64),
	]

	_pointers_ = [
		"ivarLayout",
		"name",
		"baseMethods",
		"baseProtocols",
		"ivars",
		"weakIvarLayout",
		"baseProperties",
	]


class objc_method_list_t(Structure):

	SIZE = 8

	RELATIVE_METHODS_SELECTORS_ARE_DIRECT_FLAG = 0x40000000
	RELATIVE_METHOD_FLAG = 0x80000000
	METHOD_LIST_FLAGS_MASK = 0xFFFF0000

	entsize: int
	count: int

	_fields_ = [
		("entsize", c_uint32),
		("count", c_uint32),
	]

	def usesRelativeMethods(self):
		return self.entsize & self.METHOD_LIST_FLAGS_MASK != 0

	def getEntsize(self):
		return self.entsize & ~3 & ~self.METHOD_LIST_FLAGS_MASK


class objc_method_small_t(Structure):

	SIZE = 12

	name: int
	types: int
	imp: int

	_fields_ = [
		("name", c_int32),
		("types", c_int32),
		("imp", c_int32),
	]


class objc_method_large_t(Structure):

	SIZE = 24

	name: int
	types: int
	imp: int

	_fields_ = [
		("name", c_uint64),
		("types", c_uint64),
		("imp", c_uint64),
	]

	_pointers_ = [
		"name",
		"types",
		"imp",
	]


class objc_protocol_list_t(Structure):

	SIZE = 8

	count: int

	_fields_ = [
		("count", c_uint64),
	]


class objc_protocol_t(Structure):

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

	# Fields below this point are not always present on disk.
	extendedMethodTypes: int
	demangledName: int
	classProperties: int

	_fields_ = [
		("isa", c_uint64),
		("name", c_uint64),
		("protocols", c_uint64),
		("instanceMethods", c_uint64),
		("classMethods", c_uint64),
		("optionalInstanceMethods", c_uint64),
		("optionalClassMethods", c_uint64),
		("instanceProperties", c_uint64),
		("size", c_uint32),
		("flags", c_uint32),
		("extendedMethodTypes", c_uint64),
		("demangledName", c_uint64),
		("classProperties", c_uint64),
	]

	_pointers_ = [
		"isa",
		"name",
		"protocols",
		"instanceMethods",
		"classMethods",
		"optionalInstanceMethods",
		"optionalClassMethods",
		"instanceProperties",
		"extendedMethodTypes",
		"demangledName",
		"classProperties",
	]


class objc_property_list_t(Structure):

	SIZE = 8

	entsize: int
	count: int

	_fields_ = [
		("entsize", c_uint32),
		("count", c_uint32),
	]


class objc_property_t(Structure):

	SIZE = 16

	name: int
	attributes: int

	_fields_ = [
		("name", c_uint64),
		("attributes", c_uint64),
	]

	_pointers_ = [
		"name",
		"attributes",
	]


class objc_ivar_list_t(Structure):

	SIZE = 8

	entsize: int
	count: int

	_fields_ = [
		("entsize", c_uint32),
		("count", c_uint32),
	]


class objc_ivar_t(Structure):

	SIZE = 32

	offset: int
	name: int
	type: int
	alignment: int
	size: int

	_fields_ = [
		("offset", c_uint64),
		("name", c_uint64),
		("type", c_uint64),
		("alignment", c_uint32),
		("size", c_uint32),
	]

	_pointers_ = [
		"offset",
		"name",
		"type",
	]


class objc_category_t(Structure):

	name: int
	cls: int
	instanceMethods: int
	classMethods: int
	protocols: int
	instanceProperties: int

	_fields_ = [
		("name", c_uint64),
		("cls", c_uint64),
		("instanceMethods", c_uint64),
		("classMethods", c_uint64),
		("protocols", c_uint64),
		("instanceProperties", c_uint64),
	]

	_pointers_ = [
		"name",
		"cls",
		"instanceMethods",
		"classMethods",
		"protocols",
		"instanceProperties",
	]
