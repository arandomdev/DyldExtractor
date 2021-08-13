

"""
The n_type field really contains four fields:
	unsigned char N_STAB:3,
		N_PEXT:1,
		N_TYPE:3,
		N_EXT:1;
which are used via the following masks.
"""
N_STAB = 0xe0 	# if any of these bits set, a symbolic debugging entry
N_PEXT = 0x10 	# private external symbol bit
N_TYPE = 0x0e 	# mask for the type bits
N_EXT = 0x01 	# external symbol bit, set for external symbols


# Values for N_TYPE bits of the n_type field.
N_UNDF = 0x0 	# undefined, n_sect == NO_SECT
N_ABS = 0x2 	# absolute, n_sect == NO_SECT
N_SECT = 0xe 	# defined in section number n_sect
N_PBUD = 0xc 	# prebound undefined (defined in a dylib)
N_INDR = 0xa 	# indirect


INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS = 0x40000000


"""
	The flags field of a section structure is separated into two parts a section
	type and section attributes.  The section types are mutually exclusive (it
	can only have one type) but the section attributes are not (it may have more
	than one attribute).
"""
SECTION_TYPE = 0x000000ff 			# 256 section types
SECTION_ATTRIBUTES = 0xffffff00 	# 24 section attributes

# Constants for the type of a section
S_REGULAR = 0x0 			# regular section
S_ZEROFILL = 0x1 			# zero fill on demand section
S_CSTRING_LITERALS = 0x2 	# section with only literal C strings
S_4BYTE_LITERALS = 0x3 		# section with only 4 byte literals
S_8BYTE_LITERALS = 0x4 		# section with only 8 byte literals
S_LITERAL_POINTERS = 0x5 	# section with only pointers to literals

"""
	For the two types of symbol pointers sections and the symbol stubs section
	they have indirect symbol table entries.  For each of the entries in the
	section the indirect symbol table entries, in corresponding order in the
	indirect symbol table, start at the index stored in the reserved1 field
	of the section structure.  Since the indirect symbol table entries
	correspond to the entries in the section the number of indirect symbol table
	entries is inferred from the size of the section divided by the size of the
	entries in the section.  For symbol pointers sections the size of the entries
	in the section is 4 bytes and for symbol stubs sections the byte size of the
	stubs is stored in the reserved2 field of the section structure.
"""
S_NON_LAZY_SYMBOL_POINTERS = 0x6 		# section with only non-lazy symbol pointers
S_LAZY_SYMBOL_POINTERS = 0x7 			# section with only lazy symbol pointers
S_SYMBOL_STUBS = 0x8 					# section with only symbol stubs, byte size of stub in the reserved2 field
S_MOD_INIT_FUNC_POINTERS = 0x9 			# section with only function pointers for initialization
S_MOD_TERM_FUNC_POINTERS = 0xa 			# section with only function pointers for termination
S_COALESCED = 0xb 						# section contains symbols that are to be coalesced
S_GB_ZEROFILL = 0xc 					# zero fill on demand section (that can be larger than 4 gigabytes)
S_INTERPOSING = 0xd 					# section with only pairs of function pointers for interposing
S_16BYTE_LITERALS = 0xe 				# section with only 16 byte literals
S_DTRACE_DOF = 0xf 						# section contains DTrace Object Format
S_LAZY_DYLIB_SYMBOL_POINTERS = 0x10 	# section with only lazy symbol pointers to lazy loaded dylibs


# The following are used to encode binding information
BIND_TYPE_POINTER = 1
BIND_TYPE_TEXT_ABSOLUTE32 = 2
BIND_TYPE_TEXT_PCREL32 = 3

BIND_SPECIAL_DYLIB_SELF = 0
BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE = -1
BIND_SPECIAL_DYLIB_FLAT_LOOKUP = -2
BIND_SPECIAL_DYLIB_WEAK_LOOKUP = -3

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

"""
The following are used on the flags byte of a terminal node
in the export information.
"""
EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x03
EXPORT_SYMBOL_FLAGS_KIND_REGULAR = 0x00
EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL = 0x01
EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE = 0x02
EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION = 0x04
EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08
EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10
