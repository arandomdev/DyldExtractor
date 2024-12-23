"""Structs for fixup chains

This is mainly sourced from
https://github.com/apple-oss-distributions/dyld/blob/4de7eaf4cce244fbfb9f3562d63200dbf8a6948d/include/mach-o/fixup-chains.h
"""

import sys
from ctypes import (
	c_char,
	c_uint8,
	c_uint16,
	c_uint32,
	c_uint64,
	Union,
	sizeof
)
from enum import IntEnum

from DyldExtractor.structure import Structure

class ChainedPtrStart(IntEnum):
	DYLD_CHAINED_PTR_START_NONE = 0xFFFF
	DYLD_CHAINED_PTR_START_MULTI = 0x8000
	DYLD_CHAINED_PTR_START_LAST = 0x8000

class PointerFormat(IntEnum):
	DYLD_CHAINED_PTR_ARM64E = 1
	DYLD_CHAINED_PTR_64 = 2
	DYLD_CHAINED_PTR_32 = 3
	DYLD_CHAINED_PTR_32_CACHE = 4
	DYLD_CHAINED_PTR_32_FIRMWARE = 5
	DYLD_CHAINED_PTR_64_OFFSET = 6
	DYLD_CHAINED_PTR_ARM64E_OFFSET = 7
	DYLD_CHAINED_PTR_ARM64E_KERNEL = 7
	DYLD_CHAINED_PTR_64_KERNEL_CACHE = 8
	DYLD_CHAINED_PTR_ARM64E_USERLAND = 9
	DYLD_CHAINED_PTR_ARM64E_FIRMWARE = 10
	DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE = 11
	DYLD_CHAINED_PTR_ARM64E_USERLAND24 = 12
	DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE = 13

class dyld_chained_fixups_header(Structure):
	SIZE = 28

	fixups_version: int
	starts_offset: int
	imports_offset: int
	symbols_offset: int
	imports_count: int
	imports_format: int
	symbols_format: int

	_fields_ = [
		("fixups_version", c_uint32),
		("starts_offset", c_uint32),
		("imports_offset", c_uint32),
		("symbols_offset", c_uint32),
		("imports_count", c_uint32),
		("imports_format", c_uint32),
		("symbols_format", c_uint32),
	]

class dyld_chained_starts_in_image(Structure):
	seg_count: int

	_fields_ = [
		("seg_count", c_uint32),
	]

class dyld_chained_starts_in_segment(Structure):
	size: int
	page_size: int
	pointer_format: int
	segment_offset: int
	max_valid_pointer: int
	page_count: int

	_fields_ = [
		("size", c_uint32),
		("page_size", c_uint16),
		("pointer_format", c_uint16),
		("segment_offset", c_uint64),
		("max_valid_pointer", c_uint32),
		("page_count", c_uint16),
	]

class ChainedFixupPointerOnDisk(Structure):
	target: int
	cacheLevel: int
	diversity: int
	addrDiv: int
	key: int
	_next: int
	isAuth: int

	_fields_ = [
		("target", c_uint32, 30),
		("cacheLevel", c_uint32, 2),
		("diversity", c_uint32, 16),
		("addrDiv", c_uint32, 1),
		("key", c_uint32, 2),
		("_next", c_uint32, 12),
		("isAuth", c_uint32, 1),
	]
