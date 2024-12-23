from ctypes import (
	c_int32,
	c_uint32,
	c_int64,
	c_uint64
)

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

	entsizeAndFlags: int
	count: int

	_fields_ = [
		("entsizeAndFlags", c_uint32),
		("count", c_uint32),
	]

	def usesRelativeMethods(self):
		return self.entsizeAndFlags & self.METHOD_LIST_FLAGS_MASK != 0

	def getEntsize(self):
		return self.entsizeAndFlags & ~3 & ~self.METHOD_LIST_FLAGS_MASK


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


class relative_list_list_t(Structure):
	SIZE = 8

	entsize: int
	count: int

	_fields_ = [
		("entsize", c_uint32),
		("count", c_uint32),
	]


class relative_list_t(Structure):
	SIZE = 8

	offsetAndIndex: int

	_fields_ = [("offsetAndIndex", c_uint64)]

	def getOffset(self) -> int:
		return c_int64(self.offsetAndIndex).value >> 0x10

	def getImageIndex(self) -> int:
		return self.offsetAndIndex & 0xFFFF


class objc_opt_t_V12(Structure):

	version: int
	selopt_offset: int
	headeropt_offset: int
	clsopt_offset: int

	_fields_ = [
		("version", c_uint32),
		("selopt_offset", c_int32),
		("headeropt_offset", c_int32),
		("clsopt_offset", c_int32),
	]


class objc_opt_t_V13(Structure):

	version: int
	selopt_offset: int
	headeropt_offset: int
	clsopt_offset: int
	protocolopt_offset: int

	_fields_ = [
		("version", c_uint32),
		("selopt_offset", c_int32),
		("headeropt_offset", c_int32),
		("clsopt_offset", c_int32),
		("protocolopt_offset", c_int32),
	]


class objc_opt_t_V15a(Structure):

	version: int
	flags: int
	selopt_offset: int
	headeropt_ro_offset: int
	clsopt_offset: int
	protocolopt_offset: int
	headeropt_rw_offset: int

	_fields_ = [
		("version", c_uint32),
		("flags", c_uint32),
		("selopt_offset", c_int32),
		("headeropt_ro_offset", c_int32),
		("clsopt_offset", c_int32),
		("protocolopt_offset", c_int32),
		("headeropt_rw_offset", c_int32),
	]


class objc_opt_t_V15b(Structure):

	version: int
	flags: int
	selopt_offset: int
	headeropt_ro_offset: int
	clsopt_offset: int
	unused_protocolopt_offset: int
	headeropt_rw_offset: int
	protocolopt_offset: int

	_fields_ = [
		("version", c_uint32),
		("flags", c_uint32),
		("selopt_offset", c_int32),
		("headeropt_ro_offset", c_int32),
		("clsopt_offset", c_int32),
		("unused_protocolopt_offset", c_int32),
		("headeropt_rw_offset", c_int32),
		("protocolopt_offset", c_int32),
	]


class objc_opt_t_V16(Structure):

	version: int 
	flags: int 
	selopt_offset: int 
	headeropt_ro_offset: int 
	unused_clsopt_offset: int 
	unused_protocolopt_offset: int  # This is now 0 as we've moved to the new protocolopt_offset # noqa
	headeropt_rw_offset: int 
	unused_protocolopt2_offset: int 
	largeSharedCachesClassOffset: int 
	largeSharedCachesProtocolOffset: int 
	relativeMethodSelectorBaseAddressOffset: int  # Relative method list selectors are offsets from this address # noqa

	_fields_ = [
		("version", c_uint32),
		("flags", c_uint32),
		("selopt_offset", c_int32),
		("headeropt_ro_offset", c_int32),
		("unused_clsopt_offset", c_int32),
		("unused_protocolopt_offset", c_int32),
		("headeropt_rw_offset", c_int32),
		("unused_protocolopt2_offset", c_int32),
		("largeSharedCachesClassOffset", c_int32),
		("largeSharedCachesProtocolOffset", c_int32),
		("relativeMethodSelectorBaseAddressOffset", c_int64),
	]


class objc_headeropt_ro_t(Structure):
	SIZE = 8

	count: int
	entsize: int

	_fields_ = [
		("count", c_uint32),
		("entsize", c_uint32),
	]


class objc_header_info_ro_t_64(Structure):

	mhdr_offset: int
	info_offset: int

	_fields_ = [
		("mhdr_offset", c_int64),
		("info_offset", c_int64),
	]