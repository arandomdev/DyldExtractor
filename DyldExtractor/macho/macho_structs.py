from enum import IntEnum
from ctypes import (
	Union,
	c_char, c_uint16,
	c_uint8,
	c_uint32,
	c_uint64,
	c_int32,
)

from DyldExtractor.structure import Structure


class LoadCommands(IntEnum):
	"""An Enum for all the load commands.
	"""

	"""
		After MacOS X 10.1 when a new load command is added that is required to be
		understood by the dynamic linker for the image to execute properly the
		LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
		linker sees such a load command it it does not understand will issue a
		"unknown load command required for execution" error and refuse to use the
		image.  Other load commands without this bit that are not understood will
		simply be ignored.
	"""
	LC_REQ_DYLD = 0x80000000

	# Constants for the cmd field of all load commands, the type
	LC_SEGMENT = 0x1 			# segment of this file to be mapped
	LC_SYMTAB = 0x2 			# link-edit stab symbol table info
	LC_SYMSEG = 0x3 			# link-edit gdb symbol table info (obsolete)
	LC_THREAD = 0x4 			# thread
	LC_UNIXTHREAD = 0x5 		# unix thread (includes a stack)
	LC_LOADFVMLIB = 0x6 		# load a specified fixed VM shared library
	LC_IDFVMLIB = 0x7 			# fixed VM shared library identification
	LC_IDENT = 0x8 				# object identification info (obsolete)
	LC_FVMFILE = 0x9 			# fixed VM file inclusion (internal use)
	LC_PREPAGE = 0xa 			# prepage command (internal use)
	LC_DYSYMTAB = 0xb 			# dynamic link-edit symbol table info
	LC_LOAD_DYLIB = 0xc 		# load a dynamically linked shared library
	LC_ID_DYLIB = 0xd 			# dynamically linked shared lib ident
	LC_LOAD_DYLINKER = 0xe 		# load a dynamic linker
	LC_ID_DYLINKER = 0xf 		# dynamic linker identification
	LC_PREBOUND_DYLIB = 0x10 	# modules prebound for a dynamically
								# 	linked shared library
	LC_ROUTINES = 0x11 			# image routines
	LC_SUB_FRAMEWORK = 0x12 	# sub framework
	LC_SUB_UMBRELLA = 0x13 		# sub umbrella
	LC_SUB_CLIENT = 0x14 		# sub client
	LC_SUB_LIBRARY = 0x15 		# sub library
	LC_TWOLEVEL_HINTS = 0x16 	# two-level namespace lookup hints
	LC_PREBIND_CKSUM = 0x17 	# prebind checksum

	"""
		load a dynamically linked shared library that is allowed to be missing
		(all symbols are weak imported).
	"""
	LC_LOAD_WEAK_DYLIB = (0x18 | LC_REQ_DYLD)

	LC_SEGMENT_64 = 0x19 							# 64-bit segment of this file to be
													# 	mapped
	LC_ROUTINES_64 = 0x1a 							# 64-bit image routines
	LC_UUID = 0x1b 									# the uuid
	LC_RPATH = (0x1c | LC_REQ_DYLD) 				# runpath additions
	LC_CODE_SIGNATURE = 0x1d 						# local of code signature
	LC_SEGMENT_SPLIT_INFO = 0x1e 					# local of info to split segments
	LC_REEXPORT_DYLIB = (0x1f | LC_REQ_DYLD) 		# load and re-export dylib
	LC_LAZY_LOAD_DYLIB = 0x20 						# delay load of dylib until first use
	LC_ENCRYPTION_INFO = 0x21 						# encrypted segment information
	LC_DYLD_INFO = 0x22								# compressed dyld information
	LC_DYLD_INFO_ONLY = (0x22 | LC_REQ_DYLD) 		# compressed dyld information only
	LC_LOAD_UPWARD_DYLIB = (0x23 | LC_REQ_DYLD) 	# load upward dylib
	LC_VERSION_MIN_MACOSX = 0x24 					# build for MacOSX min OS version
	LC_VERSION_MIN_IPHONEOS = 0x25 					# build for iPhoneOS min OS version
	LC_FUNCTION_STARTS = 0x26 						# compressed table of function start addresses
	LC_DYLD_ENVIRONMENT = 0x27 						# string for dyld to treat
													# 	like environment variable
	LC_MAIN = (0x28 | LC_REQ_DYLD) 					# replacement for LC_UNIXTHREAD
	LC_DATA_IN_CODE = 0x29 							# table of non-instructions in __text
	LC_SOURCE_VERSION = 0x2A 						# source version used to build binary
	LC_DYLIB_CODE_SIGN_DRS = 0x2B 					# Code signing DRs copied from linked dylibs
	LC_ENCRYPTION_INFO_64 = 0x2C 					# 64-bit encrypted segment information
	LC_LINKER_OPTION = 0x2D 						# linker options in MH_OBJECT files
	LC_LINKER_OPTIMIZATION_HINT = 0x2E 				# optimization hints in MH_OBJECT files
	LC_VERSION_MIN_TVOS = 0x2F 						# build for AppleTV min OS version
	LC_VERSION_MIN_WATCHOS = 0x30 					# build for Watch min OS version
	LC_NOTE = 0x31 									# arbitrary data included within a Mach-O file
	LC_BUILD_VERSION = 0x32 						# build for platform min OS version
	LC_DYLD_EXPORTS_TRIE = (0x33 | LC_REQ_DYLD) 	# used with linkedit_data_command, payload is trie
	LC_DYLD_CHAINED_FIXUPS = (0x34 | LC_REQ_DYLD) 	# used with linkedit_data_command
	LC_FILESET_ENTRY = (0x35 | LC_REQ_DYLD) 		# used with fileset_entry_command


class mach_header_64(Structure):

	SIZE = 32

	magic: int 			# mach magic number identifier
	cputype: int 		# cpu specifier
	cpusubtype: int 	# machine specifier
	filetype: int 		# type of file
	ncmds: int 			# number of load commands
	sizeofcmds: int 	# the size of all the load commands
	flags: int 			# flags
	reserved: int 		# reserved

	_fields_ = [
		("magic", c_uint32),
		("cputype", c_uint32),
		("cpusubtype", c_uint32),
		("filetype", c_uint32),
		("ncmds", c_uint32),
		("sizeofcmds", c_uint32),
		("flags", c_uint32),
		("reserved", c_uint32),
	]


class load_command(Structure):
	cmd: int 		# type of load command
	cmdsize: int 	# total size of command in bytes

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
	]


class UnknownLoadCommand(load_command):
	pass


class segment_command_64(Structure):
	"""
		The 64-bit segment load command indicates that a part of this file is to be
		mapped into a 64-bit task's address space.  If the 64-bit segment has
		sections then section_64 structures directly follow the 64-bit segment
		command and their size is reflected in cmdsize.

		for 64-bit architectures
	"""

	SIZE = 72

	cmd: int 		# LC_SEGMENT_64
	cmdsize: int 	# includes sizeof section_64 structs
	segname: bytes 	# segment name
	vmaddr: int 	# memory address of this segment
	vmsize: int 	# memory size of this segment
	fileoff: int 	# file offset of this segment
	filesize: int 	# amount to map from the file
	maxprot: int 	# maximum VM protection
	initprot: int 	# initial VM protection
	nsects: int 	# number of sections in segment
	flags: int 		# flags

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("segname", c_char * 16),
		("vmaddr", c_uint64),
		("vmsize", c_uint64),
		("fileoff", c_uint64),
		("filesize", c_uint64),
		("maxprot", c_int32),
		("initprot", c_int32),
		("nsects", c_uint32),
		("flags", c_uint32),
	]


class section_64(Structure):
	# for 64-bit architectures

	SIZE = 80

	sectname: bytes 	# name of this section
	segname: bytes 		# segment this section goes in
	addr: int 			# memory address of this section
	size: int 			# size in bytes of this section
	offset: int 		# file offset of this section
	align: int 			# section alignment (power of 2)
	reloff: int 		# file offset of relocation entries
	nreloc: int 		# number of relocation entries
	flags: int 			# flags (section type and attributes
	reserved1: int 		# reserved (for offset or index)
	reserved2: int 		# reserved (for count or sizeof)
	reserved3: int 		# reserved

	_fields_ = [
		("sectname", c_char * 16),
		("segname", c_char * 16),
		("addr", c_uint64),
		("size", c_uint64),
		("offset", c_uint32),
		("align", c_uint32),
		("reloff", c_uint32),
		("nreloc", c_uint32),
		("flags", c_uint32),
		("reserved1", c_uint32),
		("reserved2", c_uint32),
		("reserved3", c_uint32),
	]


class lc_str(Structure):
	offset: int 	# offset to the string

	_fields_ = [
		("offset", c_uint32),
	]


class Fvmlib(Structure):
	name: lc_str 		# library's target pathname
	minor_version: int 	# library's minor version number
	header_addr: int 	# library's header address

	_fields_ = [
		("name", lc_str),
		("minor_version", c_uint32),
		("header_addr", c_uint32),
	]


class fvmlib_command(Structure):
	cmd: int 			# LC_IDFVMLIB or LC_LOADFVMLIB
	cmdsize: int 		# includes pathname string
	fvmlib: Fvmlib		# the library identification

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("fvmlib", Fvmlib),
	]


class Dylib(Structure):
	name: lc_str 				# library's path name
	timestamp: int 				# library's build time stamp
	current_version: int 		# library's current version number
	compatibility_version: int 	# library's compatibility vers number

	_fields_ = [
		("name", lc_str),
		("timestamp", c_uint32),
		("current_version", c_uint32),
		("compatibility_version", c_uint32),
	]


class dylib_command(Structure):
	cmd: int 		# LC_ID_DYLIB, LC_LOAD_{,WEAK_}DYLIB,
					# 	LC_REEXPORT_DYLIB
	cmdsize: int 	# includes pathname string
	dylib: Dylib 	# the library identification

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("dylib", Dylib),
	]


class sub_framework_command(Structure):
	cmd: int 			# LC_SUB_FRAMEWORK
	cmdsize: int 		# includes umbrella string
	umbrella: lc_str 	# the umbrella framework name

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("umbrella", lc_str),
	]


class sub_client_command(Structure):
	cmd: int 			# LC_SUB_CLIENT
	cmdsize: int 		# includes client string
	client: lc_str 		# the client name

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("client", lc_str),
	]


class sub_umbrella_command(Structure):
	cmd: int 				# LC_SUB_UMBRELLA
	cmdsize: int 			# includes sub_umbrella string
	sub_umbrella: lc_str 	# the sub_umbrella framework name

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("sub_umbrella", lc_str),
	]


class sub_library_command(Structure):
	cmd: int 				# LC_SUB_LIBRARY
	cmdsize: int 			# includes sub_library string
	sub_library: lc_str 	# the sub_library name

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("sub_library", lc_str),
	]


class prebound_dylib_command(Structure):
	cmd: int					# LC_PREBOUND_DYLIB
	cmdsize: int				# includes strings
	name: lc_str				# library's path name
	nmodules: int				# number of modules in library
	linked_modules: lc_str		# bit vector of linked modules

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("name", lc_str),
		("nmodules", c_uint32),
		("linked_modules", lc_str),
	]


class dylinker_command(Structure):
	cmd: int 		# LC_ID_DYLINKER, LC_LOAD_DYLINKER or
					# 	LC_DYLD_ENVIRONMENT
	cmdsize: int 	# includes pathname string
	name: lc_str 	# dynamic linker's path name

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("name", lc_str),
	]


class routines_command_64(Structure):
	# for 64-bit architectures

	cmd: int 			# LC_ROUTINES_64
	cmdsize: int 		# total size of this command
	init_address: int 	# address of initialization routine
	init_module: int 	# index into the module table that
						# 	the init routine is defined in
	reserved1: int
	reserved2: int
	reserved3: int
	reserved4: int
	reserved5: int
	reserved6: int

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("init_address", c_uint64),
		("init_module", c_uint64),
		("reserved1", c_uint64),
		("reserved2", c_uint64),
		("reserved3", c_uint64),
		("reserved4", c_uint64),
		("reserved5", c_uint64),
		("reserved6", c_uint64),
	]


class symtab_command(Structure):
	cmd: int 		# LC_SYMTAB
	cmdsize: int 	# sizeof(struct symtab_command)
	symoff: int 	# symbol table offset
	nsyms: int 		# number of symbol table entries
	stroff: int 	# string table offset
	strsize: int 	# string table size in bytes

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("symoff", c_uint32),
		("nsyms", c_uint32),
		("stroff", c_uint32),
		("strsize", c_uint32),
	]


class N_un(Union):

	n_strx: int 	# index into the string table

	_fields_ = [
		("n_strx", c_uint32)
	]


class nlist_64(Structure):

	SIZE: int = 16

	n_un: N_un
	n_type: int 	# type flag, see below
	n_sect: int 	# section number or NO_SECT
	n_desc: int 	# see <mach-o/stab.h>
	n_value: int 	# value of this symbol (or stab offset)

	_fields_ = [
		("n_un", N_un),
		("n_type", c_uint8),
		("n_sect", c_uint8),
		("n_desc", c_uint16),
		("n_value", c_uint64),
	]


class dysymtab_command(Structure):
	cmd: int 				# LC_DYSYMTAB
	cmdsize: int 			# sizeof(struct dysymtab_command)

	ilocalsym: int 			# index to local symbols
	nlocalsym: int 			# number of local symbols

	iextdefsym: int 		# index to externally defined symbols
	nextdefsym: int 		# number of externally defined symbols

	iundefsym: int 			# index to undefined symbols
	nundefsym: int 			# number of undefined symbols

	tocoff: int 			# file offset to table of contents
	ntoc: int 				# number of entries in table of contents

	modtaboff: int 			# file offset to module table
	nmodtab: int 			# number of module table entries

	extrefsymoff: int 		# offset to referenced symbol table
	nextrefsyms: int 		# number of referenced symbol table entries

	indirectsymoff: int 	# file offset to the indirect symbol table
	nindirectsyms: int 		# number of indirect symbol table entries

	extreloff: int 			# offset to external relocation entries
	nextrel: int 			# number of external relocation entries

	locreloff: int 			# offset to local relocation entries
	nlocrel: int 			# number of local relocation entries

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("ilocalsym", c_uint32),
		("nlocalsym", c_uint32),
		("iextdefsym", c_uint32),
		("nextdefsym", c_uint32),
		("iundefsym", c_uint32),
		("nundefsym", c_uint32),
		("tocoff", c_uint32),
		("ntoc", c_uint32),
		("modtaboff", c_uint32),
		("nmodtab", c_uint32),
		("extrefsymoff", c_uint32),
		("nextrefsyms", c_uint32),
		("indirectsymoff", c_uint32),
		("nindirectsyms", c_uint32),
		("extreloff", c_uint32),
		("nextrel", c_uint32),
		("locreloff", c_uint32),
		("nlocrel", c_uint32),
	]


class prebind_cksum_command(Structure):
	cmd: int 		# LC_PREBIND_CKSUM
	cmdsize: int 	# sizeof(struct prebind_cksum_command)
	cksum: int 		# the check sum or zero

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("cksum", c_uint32),
	]


class uuid_command(Structure):
	cmd: int 		# LC_UUID
	cmdsize: int 	# sizeof(struct uuid_command)
	uuid: bytes 	# the 128-bit uuid

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("uuid", c_uint8 * 16),
	]


class rpath_command(Structure):
	cmd: int 		# LC_RPATH
	cmdsize: int 	# includes string
	path: int 		# path to add to run path

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("path", lc_str),
	]


class linkedit_data_command(Structure):
	cmd: int 		# LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO,
					# 	LC_FUNCTION_STARTS, LC_DATA_IN_CODE,
					# 	LC_DYLIB_CODE_SIGN_DRS,
					# 	LC_LINKER_OPTIMIZATION_HINT,
					# 	LC_DYLD_EXPORTS_TRIE, or
					# 	LC_DYLD_CHAINED_FIXUPS.
	cmdsize: int 	# sizeof(struct linkedit_data_command)
	dataoff: int 	# file offset of data in __LINKEDIT segment
	datasize: int 	# file size of data in __LINKEDIT segment

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("dataoff", c_uint32),
		("datasize", c_uint32),
	]


class fileset_entry_command(Structure):
	cmd: int 		# LC_FILESET_ENTRY
	cmdsize: int 	# includes id string
	vmaddr: int 	# memory address of the dylib
	fileoff: int 	# file offset of the dylib
	entry_id: int 	# contained entry id
	reserved: int 	# entry_id is 32-bits long, so this is the reserved padding

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("vmaddr", c_uint64),
		("fileoff", c_uint64),
		("entry_id", lc_str),
		("reserved", c_uint32),
	]


class encryption_info_command_64(Structure):
	cmd: int 		# LC_ENCRYPTION_INFO_64
	cmdsize: int 	# sizeof(struct encryption_info_command_64)
	cryptoff: int 	# file offset of encrypted range
	cryptsize: int 	# file size of encrypted range
	cryptid: int 	# which encryption system,
					# 	0 means not-encrypted yet
	pad: int 		# padding to make this struct's size a multiple
					# 	of 8 bytes

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("cryptoff", c_uint32),
		("cryptsize", c_uint32),
		("cryptid", c_uint32),
		("pad", c_uint32),
	]


class version_min_command(Structure):
	cmd: int 		# LC_VERSION_MIN_MACOSX or
					# 	LC_VERSION_MIN_IPHONEOS or
					# 	LC_VERSION_MIN_WATCHOS or
					# 	LC_VERSION_MIN_TVOS
	cmdsize: int 	# sizeof(struct min_version_command)
	version: int 	# X.Y.Z is encoded in nibbles xxxx.yy.zz
	sdk: int		# X.Y.Z is encoded in nibbles xxxx.yy.zz

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("version", c_uint32),
		("sdk", c_uint32),
	]


class build_version_command(Structure):
	cmd: int 		# LC_BUILD_VERSION
	cmdsize: int 	# sizeof(struct build_version_command) plus
					# 	ntools * sizeof(struct build_tool_version)
	platform: int 	# platform
	minos: int 		# X.Y.Z is encoded in nibbles xxxx.yy.zz
	sdk: int 		# X.Y.Z is encoded in nibbles xxxx.yy.zz
	ntools: int 	# number of tool entries following this

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("platform", c_uint32),
		("minos", c_uint32),
		("sdk", c_uint32),
		("ntools", c_uint32),
	]


class dyld_info_command(Structure):
	cmd: int 				# LC_DYLD_INFO or LC_DYLD_INFO_ONLY
	cmdsize: int 			# sizeof(struct dyld_info_command)

	rebase_off: int 		# file offset to rebase info
	rebase_size: int 		# size of rebase info

	bind_off: int 			# file offset to binding info
	bind_size: int 			# size of binding info

	weak_bind_off: int 		# file offset to weak binding info
	weak_bind_size: int 	# size of weak binding info

	lazy_bind_off: int 		# file offset to lazy binding info
	lazy_bind_size: int 	# size of lazy binding infs

	export_off: int 		# file offset to lazy binding info
	export_size: int 		# size of lazy binding infs

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("rebase_off", c_uint32),
		("rebase_size", c_uint32),
		("bind_off", c_uint32),
		("bind_size", c_uint32),
		("weak_bind_off", c_uint32),
		("weak_bind_size", c_uint32),
		("lazy_bind_off", c_uint32),
		("lazy_bind_size", c_uint32),
		("export_off", c_uint32),
		("export_size", c_uint32),
	]


class linker_option_command(Structure):
	cmd: int 	# LC_LINKER_OPTION only used in MH_OBJECT filetypes
	cmdsize: int
	count: int 	# number of strings

	# concatenation of zero terminated UTF8 strings.
	#   Zero filled at end to align

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("count", c_uint32),
	]


class symseg_command(Structure):
	cmd: int		# LC_SYMSEG
	cmdsize: int 	# sizeof(struct symseg_command)
	offset: int		# symbol segment offset
	size: int		# symbol segment size in bytes

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("offset", c_uint32),
		("size", c_uint32),
	]


class ident_command(Structure):
	cmd: int 		# LC_IDENT
	cmdsize: int 	# strings that follow this command

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
	]


class fvmfile_command(Structure):
	cmd: int 			# LC_FVMFILE
	cmdsize: int 		# includes pathname string
	name: lc_str 		# files pathname
	header_addr: int 	# files virtual address

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("name", lc_str),
		("header_addr", c_uint32),
	]


class entry_point_command(Structure):
	cmd: int 		# LC_MAIN only used in MH_EXECUTE filetypes
	cmdsize: int 	# 24
	entryoff: int 	# file (__TEXT) offset of main()
	stacksize: int 	# if not zero, initial stack size

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("entryoff", c_uint64),
		("stacksize", c_uint64),
	]


class source_version_command(Structure):
	cmd: int 		# LC_SOURCE_VERSION
	cmdsize: int 	# 16
	version: int 	# A.B.C.D.E packed as a24.b10.c10.d10.e10

	_fields_ = [
		("cmd", c_uint32),
		("cmdsize", c_uint32),
		("version", c_uint64),
	]


LoadCommandMap = {
	# Provides a mapping between a load command and its structure.

	# LoadCommands.LC_SEGMENT: None,
	LoadCommands.LC_SYMTAB: symtab_command,
	LoadCommands.LC_SYMSEG: symseg_command,
	# LoadCommands.LC_THREAD: None,
	# LoadCommands.LC_UNIXTHREAD: None,
	LoadCommands.LC_LOADFVMLIB: fvmlib_command,
	LoadCommands.LC_IDFVMLIB: fvmlib_command,
	LoadCommands.LC_IDENT: ident_command,
	LoadCommands.LC_FVMFILE: fvmfile_command,
	# LoadCommands.LC_PREPAGE: None,
	LoadCommands.LC_DYSYMTAB: dysymtab_command,
	LoadCommands.LC_LOAD_DYLIB: dylib_command,
	LoadCommands.LC_ID_DYLIB: dylib_command,
	LoadCommands.LC_LOAD_DYLINKER: dylinker_command,
	LoadCommands.LC_ID_DYLINKER: dylinker_command,
	LoadCommands.LC_PREBOUND_DYLIB: prebound_dylib_command,
	# LoadCommands.LC_ROUTINES: None,
	LoadCommands.LC_SUB_FRAMEWORK: sub_framework_command,
	LoadCommands.LC_SUB_UMBRELLA: sub_umbrella_command,
	LoadCommands.LC_SUB_CLIENT: sub_client_command,
	LoadCommands.LC_SUB_LIBRARY: sub_library_command,
	# LoadCommands.LC_TWOLEVEL_HINTS: None,
	LoadCommands.LC_PREBIND_CKSUM: prebind_cksum_command,
	LoadCommands.LC_LOAD_WEAK_DYLIB: dylib_command,
	LoadCommands.LC_SEGMENT_64: segment_command_64,
	LoadCommands.LC_ROUTINES_64: routines_command_64,
	LoadCommands.LC_UUID: uuid_command,
	LoadCommands.LC_RPATH: rpath_command,
	LoadCommands.LC_CODE_SIGNATURE: linkedit_data_command,
	LoadCommands.LC_SEGMENT_SPLIT_INFO: linkedit_data_command,
	LoadCommands.LC_REEXPORT_DYLIB: dylib_command,
	LoadCommands.LC_LAZY_LOAD_DYLIB: dylib_command,
	# LoadCommands.LC_ENCRYPTION_INFO: None,
	LoadCommands.LC_DYLD_INFO: dyld_info_command,
	LoadCommands.LC_DYLD_INFO_ONLY: dyld_info_command,
	LoadCommands.LC_LOAD_UPWARD_DYLIB: dylib_command,
	LoadCommands.LC_VERSION_MIN_MACOSX: version_min_command,
	LoadCommands.LC_VERSION_MIN_IPHONEOS: version_min_command,
	LoadCommands.LC_FUNCTION_STARTS: linkedit_data_command,
	LoadCommands.LC_DYLD_ENVIRONMENT: dylinker_command,
	LoadCommands.LC_MAIN: entry_point_command,
	LoadCommands.LC_DATA_IN_CODE: linkedit_data_command,
	LoadCommands.LC_SOURCE_VERSION: source_version_command,
	LoadCommands.LC_DYLIB_CODE_SIGN_DRS: linkedit_data_command,
	LoadCommands.LC_ENCRYPTION_INFO_64: encryption_info_command_64,
	LoadCommands.LC_LINKER_OPTION: linker_option_command,
	LoadCommands.LC_LINKER_OPTIMIZATION_HINT: linkedit_data_command,
	LoadCommands.LC_VERSION_MIN_TVOS: version_min_command,
	LoadCommands.LC_VERSION_MIN_WATCHOS: version_min_command,
	# LoadCommands.LC_NOTE: None,
	LoadCommands.LC_BUILD_VERSION: build_version_command,
	LoadCommands.LC_DYLD_EXPORTS_TRIE: linkedit_data_command,
	LoadCommands.LC_DYLD_CHAINED_FIXUPS: linkedit_data_command,
	LoadCommands.LC_FILESET_ENTRY: fileset_entry_command,
}


class nlist_64(Structure):

	SIZE = 16

	n_strx: int 	# index into the string table
	n_type: int 	# type flag, see below
	n_sect: int 	# section number or NO_SECT
	n_desc: int 	# see <mach-o/stab.h>
	n_value: int 	# value of this symbol (or stab offset)

	_fields_ = [
		("n_strx", c_uint32),
		("n_type", c_uint8),
		("n_sect", c_uint8),
		("n_desc", c_uint16),
		("n_value", c_uint64),
	]
