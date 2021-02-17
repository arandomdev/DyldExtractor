from __future__ import annotations

from enum import IntEnum
from io import BufferedReader
from typing import List, ClassVar

from DyldExtractor.Structure import Structure


__all__ = [
	"LoadCommands",
	"Export",
	"NList",
	"Rebase",
	"Bind",
	"mach_header_64",
	"load_command",
	"dylib_command",
	"section_64",
	"segment_command_64",
	"dyld_info_command",
	"symtab_command",
	"dysymtab_command",
	"linkedit_data_command",
	"uuid_command",
	"build_version_command",
	"source_version_command",
	"encryption_info_command_64",
	"rpath_command",
	"nlist_64",
	"sub_framework_command",
	"sub_client_command",
	"routines_command_64",
	"version_min_command"
]


class LoadCommands(IntEnum):
	LC_SEGMENT = 0x1					# segment of this file to be mapped
	LC_SYMTAB = 0x2						# link-edit stab symbol table info
	LC_SYMSEG = 0x3						# link-edit gdb symbol table info (obsolete)
	LC_THREAD = 0x4						# thread
	LC_UNIXTHREAD = 0x5					# unix thread (includes a stack)
	LC_LOADFVMLIB = 0x6					# load a specified fixed VM shared library
	LC_IDFVMLIB = 0x7					# fixed VM shared library identification
	LC_IDENT = 0x8						# object identification info (obsolete)
	LC_FVMFILE = 0x9					# fixed VM file inclusion (internal use)
	LC_PREPAGE = 0xa     				# prepage command (internal use)
	LC_DYSYMTAB = 0xb					# dynamic link-edit symbol table info
	LC_LOAD_DYLIB = 0xc					# load a dynamically linked shared library
	LC_ID_DYLIB = 0xd					# dynamically linked shared lib ident
	LC_LOAD_DYLINKER = 0xe				# load a dynamic linker
	LC_ID_DYLINKER = 0xf				# dynamic linker identification
	LC_PREBOUND_DYLIB = 0x10			# modules prebound for a dynamically
	
	# linked shared library
	LC_ROUTINES = 0x11					# image routines
	LC_SUB_FRAMEWORK = 0x12				# sub framework
	LC_SUB_UMBRELLA = 0x13				# sub umbrella
	LC_SUB_CLIENT = 0x14				# sub client
	LC_SUB_LIBRARY = 0x15				# sub library
	LC_TWOLEVEL_HINTS = 0x16			# two-level namespace lookup hints
	LC_PREBIND_CKSUM = 0x17				# prebind checksum

	"""
		load a dynamically linked shared library that is allowed to be missing
		(all symbols are weak imported).
	"""
	LC_LOAD_WEAK_DYLIB = 0x80000018

	LC_SEGMENT_64 = 0x19				# 64-bit segment of this file to be mapped
	LC_ROUTINES_64 = 0x1a				# 64-bit image routines
	LC_UUID =	0x1b					# the uuid
	LC_RPATH = 0x8000001c    			# runpath additions
	LC_CODE_SIGNATURE = 0x1d			# local of code signature
	LC_SEGMENT_SPLIT_INFO = 0x1e 		# local of info to split segments
	LC_REEXPORT_DYLIB = 0x8000001f 		# load and re-export dylib
	LC_LAZY_LOAD_DYLIB = 0x20			# delay load of dylib until first use
	LC_ENCRYPTION_INFO = 0x21			# encrypted segment information
	LC_DYLD_INFO = 0x22					# compressed dyld information
	LC_DYLD_INFO_ONLY = 0x80000022		# compressed dyld information only
	LC_LOAD_UPWARD_DYLIB = 0x80000023 	# load upward dylib
	LC_VERSION_MIN_MACOSX = 0x24		# build for MacOSX min OS version
	LC_VERSION_MIN_IPHONEOS = 0x25 		# build for iPhoneOS min OS version
	LC_FUNCTION_STARTS = 0x26 			# compressed table of function start addresses
	LC_DYLD_ENVIRONMENT = 0x27 			# string for dyld to treat like environment variable
	LC_MAIN = 0x80000028 				# replacement for LC_UNIXTHREAD
	LC_DATA_IN_CODE = 0x29 				# table of non-instructions in __text
	LC_SOURCE_VERSION = 0x2A 			# source version used to build binary
	LC_DYLIB_CODE_SIGN_DRS = 0x2B 		# Code signing DRs copied from linked dylibs
	LC_ENCRYPTION_INFO_64 = 0x2C		# 64-bit encrypted segment information
	LC_LINKER_OPTION = 0x2D 			# linker options in MH_OBJECT files
	LC_LINKER_OPTIMIZATION_HINT = 0x2E	# optimization hints in MH_OBJECT files
	LC_VERSION_MIN_TVOS = 0x2F 			# build for AppleTV min OS version
	LC_VERSION_MIN_WATCHOS = 0x30 		# build for Watch min OS version
	LC_NOTE = 0x31 						# arbitrary data included within a Mach-O file
	LC_BUILD_VERSION = 0x32 			# build for platform min OS version
	LC_DYLD_EXPORTS_TRIE = 0x80000033 	# used with linkedit_data_command, payload is trie
	LC_DYLD_CHAINED_FIXUPS = 0x80000034	# used with linkedit_data_command


class Export(IntEnum):
	# The following are used on the flags byte of a terminal node
	# in the export information.

	EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x03
	EXPORT_SYMBOL_FLAGS_KIND_REGULAR = 0x00
	EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL = 0x01
	EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE = 0x02
	EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION = 0x04
	EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08
	EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10


class NList(IntEnum):
	N_STAB = 0xe0 	# if any of these bits set, a symbolic debugging entry */
	N_PEXT = 0x10 	# private external symbol bit */
	N_TYPE = 0x0e 	# mask for the type bits */
	N_EXT = 0x01 	# external symbol bit, set for external symbols */
	
	N_UNDF = 0x0 	# undefined, n_sect == NO_SECT */
	N_ABS = 0x2 	# absolute, n_sect == NO_SECT */
	N_SECT = 0xe 	# defined in section number n_sect */
	N_PBUD = 0xc 	# prebound undefined (defined in a dylib) */
	N_INDR = 0xa 	# indirect */


class Rebase(IntEnum):
	REBASE_TYPE_POINTER = 1
	REBASE_TYPE_TEXT_ABSOLUTE32 = 2
	REBASE_TYPE_TEXT_PCREL32 = 3

	REBASE_OPCODE_MASK = 0xF0
	REBASE_IMMEDIATE_MASK = 0x0F
	REBASE_OPCODE_DONE = 0x00
	REBASE_OPCODE_SET_TYPE_IMM = 0x10
	REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x20
	REBASE_OPCODE_ADD_ADDR_ULEB = 0x30
	REBASE_OPCODE_ADD_ADDR_IMM_SCALED = 0x40
	REBASE_OPCODE_DO_REBASE_IMM_TIMES = 0x50
	REBASE_OPCODE_DO_REBASE_ULEB_TIMES = 0x60
	REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB = 0x70
	REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80


class Bind(IntEnum):
	BIND_TYPE_POINTER = 1
	BIND_TYPE_TEXT_ABSOLUTE32 = 2
	BIND_TYPE_TEXT_PCREL32 = 3

	BIND_SPECIAL_DYLIB_SELF = 0
	BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE = 1
	BIND_SPECIAL_DYLIB_FLAT_LOOKUP = 2
	BIND_SPECIAL_DYLIB_WEAK_LOOKUP = 3

	BIND_SYMBOL_FLAGS_WEAK_IMPORT = 0x1
	BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION = 0x8

	BIND_OPCODE_MASK = 0xF0
	BIND_IMMEDIATE_MASK = 0x0F
	BIND_OPCODE_DONE = 0x00
	BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
	BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
	BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30
	BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
	BIND_OPCODE_SET_TYPE_IMM = 0x50
	BIND_OPCODE_SET_ADDEND_SLEB = 0x60
	BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
	BIND_OPCODE_ADD_ADDR_ULEB = 0x80
	BIND_OPCODE_DO_BIND = 0x90
	BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0
	BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
	BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0
	BIND_OPCODE_THREADED = 0xD0
	BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB = 0x00
	BIND_SUBOPCODE_THREADED_APPLY = 0x01


class mach_header_64(Structure):
	
	SIZE: ClassVar[int] = 32

	magic: bytes	# mach magic number identifier
	cputype: int	# cpu specifier
	cpusubtype: int	# machine specifier
	filetype: int	# type of file
	ncmds: int		# number of load commands
	sizeofcmds: int	# the size of all the load commands
	flags: int		# flags
	reserved: int	# reserved

	_fields_ = (
		("magic", 4),
		("cputype", "<I"),
		("cpusubtype", "<I"),
		("filetype", "<I"),
		("ncmds", "<I"),
		("sizeofcmds", "<I"),
		("flags", "<I"),
		("reserved", "<I"),
	)


class load_command(Structure):
	
	SIZE: ClassVar[int] = 8

	cmd: int		# type of load command
	cmdsize: int	# total size of command in bytes

	_fields_ = (
		("cmd", "<I"),
		("cmdsize", "<I"),
	)


class dylib_command(load_command):

	dylibData: bytes

	_fields_ = ()
	
	@classmethod
	def parse(cls, buffer: BufferedReader, fileOffset: int, loadData: bool = True) -> dylib_command:
		inst = super().parse(buffer, fileOffset, loadData=loadData)
		
		inst.dylibData = buffer.read(inst.cmdsize - inst.SIZE)
		return inst
	
	def asBytes(self) -> bytes:
		data = super().asBytes()

		data += self.dylibData
		return data


class section_64(Structure):
	
	SIZE: ClassVar[int] = 80

	sectname: bytes	# name of this section
	segname: bytes	# segment this section goes in
	addr: int		# memory address of this section
	size: int		# size in bytes of this section
	offset: int		# file offset of this section
	align: int		# section alignment (power of 2)
	reloff: int		# file offset of relocation entries
	nreloc: int		# number of relocation entries
	flags: int		# flags (section type and attributes
	reserved1: int	# reserved (for offset or index)
	reserved2: int	# reserved (for count or sizeof)
	reserved3: int	# reserved

	sectionData: bytes

	_fields_ = (
		("sectname", 16),
		("segname", 16),
		("addr", "<Q"),
		("size", "<Q"),
		("offset", "<I"),
		("align", "<I"),
		("reloff", "<I"),
		("nreloc", "<I"),
		("flags", "<I"),
		("reserved1", "<I"),
		("reserved2", "<I"),
		("reserved3", "<I"),
	)
		
	def loadData(self) -> None:
		self._buffer.seek(self.offset)

		self.sectionData = self._buffer.read(self.size)
		pass


class segment_command_64(load_command):
	
	SIZE: ClassVar[int] = 72

	segname: bytes	# segment name
	vmaddr: int		# memory address of this segment
	vmsize: int		# memory size of this segment
	fileoff: int	# file offset of this segment
	filesize: int	# amount to map from the file
	maxprot: int	# maximum VM protection
	initprot: int	# initial VM protection
	nsects: int		# number of sections in segment
	flags: int		# flags

	sections: List[section_64]

	_fields_ = (
		("segname", 16),
		("vmaddr", "<Q"),
		("vmsize", "<Q"),
		("fileoff", "<Q"),
		("filesize", "<Q"),
		("maxprot", "<I"),
		("initprot", "<I"),
		("nsects", "<I"),
		("flags", "<I"),
	)

	@classmethod
	def parse(cls, buffer: BufferedReader, fileOffset: int, loadData: bool = True) -> segment_command_64:
		inst = super().parse(buffer, fileOffset, loadData=loadData)

		inst.sections = []
		for i in range(inst.nsects):
			sectOff = (i * section_64.SIZE) + inst.SIZE + fileOffset
			inst.sections.append(section_64.parse(buffer, sectOff, loadData=loadData))
		
		return inst


class dyld_info_command(load_command):
	
	rebase_off: int		# file offset to rebase info
	rebase_size: int	# size of rebase info
	bind_off: int		# file offset to binding info
	bind_size: int		# size of binding info
	weak_bind_off: int	# file offset to weak binding info
	weak_bind_size: int	# size of weak binding info
	lazy_bind_off: int	# file offset to lazy binding info
	lazy_bind_size: int	# size of lazy binding infs
	export_off: int		# file offset to lazy binding info
	export_size: int	# size of lazy binding infs

	rebaseData: bytes
	bindData: bytes
	weak_bindData: bytes
	lazy_bindData: bytes
	exportData: bytes

	_fields_ = (
		("rebase_off", "<I"),
		("rebase_size", "<I"),
		("bind_off", "<I"),
		("bind_size", "<I"),
		("weak_bind_off", "<I"),
		("weak_bind_size", "<I"),
		("lazy_bind_off", "<I"),
		("lazy_bind_size", "<I"),
		("export_off", "<I"),
		("export_size", "<I"),
	)

	def loadData(self) -> None:
		self._buffer.seek(self.rebase_off)

		self.rebaseData = self._buffer.read(self.rebase_size)
		self._buffer.seek(self.bind_off)
		self.bindData = self._buffer.read(self.bind_size)
		self._buffer.seek(self.weak_bind_off)
		self.weak_bindData = self._buffer.read(self.weak_bind_size)
		self._buffer.seek(self.lazy_bind_off)
		self.lazy_bindData = self._buffer.read(self.lazy_bind_size)
		self._buffer.seek(self.export_off)
		self.exportData = self._buffer.read(self.export_size)
		pass


class symtab_command(load_command):
	
	symoff: int		# symbol table offset
	nsyms: int		# number of symbol table entries
	stroff: int		# string table offset
	strsize: int	# string table size in bytes

	symbolData: bytes
	stringData: bytes

	_fields_ = (
		("symoff", "<I"),
		("nsyms", "<I"),
		("stroff", "<I"),
		("strsize", "<I"),
	)

	def loadData(self) -> None:
		self._buffer.seek(self.symoff)
		self.symbolData = self._buffer.read(self.nsyms * 16) # size of nlist_64

		self._buffer.seek(self.stroff)
		self.stringData = self._buffer.read(self.strsize)
		pass


class dysymtab_command(load_command):

	ilocalsym: int		# index to local symbols
	nlocalsym: int		# number of local symbols
	iextdefsym: int		# index to externally defined symbols
	nextdefsym: int		# number of externally defined symbols
	iundefsym: int		# index to undefined symbols
	nundefsym: int		# number of undefined symbols
	
	tocoff: int			# file offset to table of contents
	ntoc: int			# number of entries in table of contents
	modtaboff: int		# file offset to module table
	nmodtab: int		# number of module table entries
	extrefsymoff: int	# offset to referenced symbol table
	nextrefsyms: int	# number of referenced symbol table entries
	indirectsymoff: int	# file offset to the indirect symbol table
	nindirectsyms: int	# number of indirect symbol table entries
	extreloff: int		# offset to external relocation entries
	nextrel: int		# number of external relocation entries
	locreloff: int		# offset to local relocation entries
	nlocrel: int		# number of local relocation entries

	tocData: bytes
	modtabData: bytes
	extrefsymsData: bytes
	indirectsymsData: bytes
	extrelData: bytes
	locrelData: bytes

	_fields_ = (
		("ilocalsym", "<I"),
		("nlocalsym", "<I"),
		("iextdefsym", "<I"),
		("nextdefsym", "<I"),
		("iundefsym", "<I"),
		("nundefsym", "<I"),
		("tocoff", "<I"),
		("ntoc", "<I"),
		("modtaboff", "<I"),
		("nmodtab", "<I"),
		("extrefsymoff", "<I"),
		("nextrefsyms", "<I"),
		("indirectsymoff", "<I"),
		("nindirectsyms", "<I"),
		("extreloff", "<I"),
		("nextrel", "<I"),
		("locreloff", "<I"),
		("nlocrel", "<I"),
	)

	def loadData(self) -> None:
		self._buffer.seek(self.tocoff)
		self.tocData = self._buffer.read(self.ntoc * 8) # size of dylib_table_of_contents
		self._buffer.seek(self.modtaboff)
		self.modtabData = self._buffer.read(self.nmodtab * 56) # size of dylib_module_64
		self._buffer.seek(self.extrefsymoff)
		self.extrefsymsData = self._buffer.read(self.nextrefsyms * 4) # size of dylib_reference
		self._buffer.seek(self.indirectsymoff)
		self.indirectsymsData = self._buffer.read(self.nindirectsyms * 4) # 32bit index into the symbol entry table
		self._buffer.seek(self.extreloff)
		self.extrelData = self._buffer.read(self.nextrel * 8)
		self._buffer.seek(self.locreloff)
		self.locrelData = self._buffer.read(self.nlocrel * 8)
		pass


class linkedit_data_command(load_command):
	
	dataoff: int
	datasize: int

	linkeditData: bytes

	_fields_ = (
		("dataoff", "<I"),
		("datasize", "<I"),
	)

	def loadData(self) -> None:
		self._buffer.seek(self.dataoff)
		self.linkeditData = self._buffer.read(self.datasize)
		pass


class uuid_command(load_command):
	
	uuid: bytes

	_fields_ = (
		("uuid", 16),
	)


class build_version_command(load_command):

	SIZE: ClassVar[int] = 24

	# cmdsize sizeof(struct build_version_command) plus ntools * sizeof(struct build_tool_version)
	
	platform: bytes
	minos: bytes
	sdk: bytes
	ntools: bytes

	buildToolData: bytes

	_fields_ = (
		("platform", "<I"),
		("minos", "<I"),
		("sdk", "<I"),
		("ntools", "<I"),
	)

	@classmethod
	def parse(cls, buffer: BufferedReader, fileOffset: int, loadData: bool = True) -> build_version_command:
		inst = super().parse(buffer, fileOffset)

		inst.buildToolData = buffer.read(inst.cmdsize - inst.SIZE)
		return inst

	def asBytes(self) -> bytes:
		data = super().asBytes()

		data += self.buildToolData
		return data


class source_version_command(load_command):
	
	version: int	# A.B.C.D.E packed as a24.b10.c10.d10.e10

	_fields_ = (
		("version", "<Q"),
	)


class encryption_info_command_64(load_command):
	
	cryptoff: int	# file offset of encrypted range
	cryptsize: int	# file size of encrypted range
	cryptid: int	# which encryption system, 0 means not-encrypted yet
	pad: int		# padding to make this struct's size a multiple of 8 bytes

	_fields_ = (
		("cryptoff", "<I"),
		("cryptsize", "<I"),
		("cryptid", "<I"),
		("pad", "<I"),
	)


class rpath_command(load_command):

	path: bytes

	_fields_ = ()

	@classmethod
	def parse(cls, buffer: BufferedReader, fileOffset: int, loadData: bool = True) -> rpath_command:
		inst = super().parse(buffer, fileOffset)
		
		inst.path = buffer.read(inst.cmdsize - inst.SIZE)
		return inst
	
	def asBytes(self) -> bytes:
		data = super().asBytes()

		data += self.path
		return data


class nlist_64(Structure):

	SIZE: ClassVar[int] = 16
	
	n_strx: int 	# index into the string table
	n_type: int 	# type flag, see below
	n_sect: int 	# section number or NO_SECT
	n_desc: int 	# see <mach-o/stab.h>
	n_value: int 	# value of this symbol (or stab offset)

	_fields_ = (
		("n_strx", "<I"),
		("n_type", "<B"),
		("n_sect", "<B"),
		("n_desc", "<H"),
		("n_value", "<Q"),
	)


class sub_framework_command(load_command):
	
	# cmd			# LC_SUB_FRAMEWORK
	# cmdsize		# includes umbrella string
	umbrella: bytes	# the umbrella framework name

	_fields_ = ()

	@classmethod
	def parse(cls, buffer: BufferedReader, fileOffset: int, loadData: bool = True) -> sub_framework_command:
		inst = super().parse(buffer, fileOffset)
		
		inst.umbrella = buffer.read(inst.cmdsize - inst.SIZE)
		return inst
	
	def asBytes(self) -> bytes:
		data = super().asBytes()

		data += self.umbrella
		return data


class sub_client_command(load_command):
	
	# cmd			# LC_SUB_CLIENT
	# cmdsize		# includes client string
	client: bytes	# the client name

	_fields_ = ()

	@classmethod
	def parse(cls, buffer: BufferedReader, fileOffset: int, loadData: bool = True) -> sub_client_command:
		inst = super().parse(buffer, fileOffset)
		
		inst.client = buffer.read(inst.cmdsize - inst.SIZE)
		return inst
	
	def asBytes(self) -> bytes:
		data = super().asBytes()

		data += self.client
		return data


class routines_command_64(load_command):

	init_address: int	# address of initialization routine
	init_module: int	# index into the module table that the init routine is defined in
	reserved1: int
	reserved2: int
	reserved3: int
	reserved4: int
	reserved5: int
	reserved6: int

	_fields_ = (
		("init_address", "<Q"),
		("init_module", "<Q"),
		("reserved1", "<Q"),
		("reserved2", "<Q"),
		("reserved3", "<Q"),
		("reserved4", "<Q"),
		("reserved5", "<Q"),
		("reserved6", "<Q"),
	)


class version_min_command(load_command):

	cmd: int 		# LC_VERSION_MIN_MACOSX or
					# LC_VERSION_MIN_IPHONEOS or
					# LC_VERSION_MIN_WATCHOS or
					# LC_VERSION_MIN_TVOS
	cmdsize: int 	# sizeof(struct min_version_command) */
	version: int 	# X.Y.Z is encoded in nibbles xxxx.yy.zz */
	sdk: int 		# X.Y.Z is encoded in nibbles xxxx.yy.zz */

	_fields_ = (
		("cmd", "<I"),
		("cmdsize", "<I"),
		("version", "<I"),
		("sdk", "<I"),
	)