from DyldExtractor import MachO

class OffsetConverter(object):
	
	"""Adjusts a dyld macho file's offset and addresses.

	This class takes a Macho file parsed from the dyld cache
	and changes its file offsets so that it makes sense as
	an individual file.
	"""

	def __init__(self, machoFile: MachO.MachoFile) -> None:
		self.dataHead = machoFile.machHeader.sizeofcmds + MachO.mach_header_64.SIZE

		self.machoFile = machoFile
		pass

	def convert(self) -> None:
		self.processLoadCommands()
		self.processSymbolTable()
		self.fixLinkEdit()
		pass

	def processLoadCommands(self) -> None:
		for command in self.machoFile.loadCommands:

			if command.cmd == MachO.LoadCommands.LC_SEGMENT_64:
				self.processSegment(command)
				pass

			elif (
				command.cmd == MachO.LoadCommands.LC_DYLD_INFO
				or command.cmd == MachO.LoadCommands.LC_DYLD_INFO_ONLY
			):
				if len(command.rebaseData):
					command.rebase_off = self.dataHead
					self.dataHead += len(command.rebaseData)
				if len(command.bindData):
					command.bind_off = self.dataHead
					self.dataHead += len(command.bindData)
				if len(command.weak_bindData):
					command.weak_bind_off = self.dataHead
					self.dataHead += len(command.weak_bindData)
				if len(command.lazy_bindData):
					command.lazy_bind_off = self.dataHead
					self.dataHead += len(command.lazy_bindData)
				if len(command.exportData):
					command.export_off = self.dataHead
					self.dataHead += len(command.exportData)
				pass

			elif (
				command.cmd == MachO.LoadCommands.LC_FUNCTION_STARTS
				or command.cmd == MachO.LoadCommands.LC_DATA_IN_CODE
			):
				command.dataoff = self.dataHead
				self.dataHead += command.datasize
				pass

			elif (
				command.cmd == MachO.LoadCommands.LC_SYMTAB
				or command.cmd == MachO.LoadCommands.LC_DYSYMTAB
			):
				# These are located at the end of the file,
				# we'll fix these later
				pass

			elif (
				command.cmd == MachO.LoadCommands.LC_BUILD_VERSION
				or command.cmd == MachO.LoadCommands.LC_ID_DYLIB
				or command.cmd == MachO.LoadCommands.LC_LOAD_DYLIB
				or command.cmd == MachO.LoadCommands.LC_REEXPORT_DYLIB
				or command.cmd == MachO.LoadCommands.LC_LOAD_WEAK_DYLIB
				or command.cmd == MachO.LoadCommands.LC_LOAD_UPWARD_DYLIB
				or command.cmd == MachO.LoadCommands.LC_UUID
				or command.cmd == MachO.LoadCommands.LC_SOURCE_VERSION
				or command.cmd == MachO.LoadCommands.LC_SUB_FRAMEWORK
				or command.cmd == MachO.LoadCommands.LC_SUB_CLIENT
				or command.cmd == MachO.LoadCommands.LC_ROUTINES_64
				or command.cmd == MachO.LoadCommands.LC_ENCRYPTION_INFO_64
				or command.cmd == MachO.LoadCommands.LC_RPATH
			):
				# These don't have any data
				pass

			else:
				raise Exception("Unknown load command: " + MachO.LoadCommands(command.cmd).name)
		pass

	def processSegment(self, seg: MachO.segment_command_64) -> None:
		PAGE_SIZE = 0x4000

		# A segment must be page aligned
		if not b"__TEXT\x00" in seg.segname:
			padding = PAGE_SIZE - (self.dataHead % PAGE_SIZE)
			self.dataHead += padding

		# The __TEXT segment starts from the beginning.
		segStart = 0 if b"__TEXT\x00" in seg.segname else self.dataHead

		# set the offsets for each section
		for sect in seg.sections:

			# add any padding if needed
			offsetInSeg = sect.addr - seg.vmaddr
			padding = offsetInSeg - (self.dataHead - segStart)
			self.dataHead += padding

			# sections like "bss" and "common" don't have data.
			if sect.offset:
				sect.offset = self.dataHead

			# advance the data head
			self.dataHead += sect.size
		
		seg.fileoff = segStart
		seg.filesize = self.dataHead - segStart
		pass

	def processSymbolTable(self) -> None:
		"""Adjusts the symtab and dysymtab.

		The symbol table needs to be at the end of the file,
		with the entries coming first and then the string
		table.
		"""
		symCmd = self.machoFile.getLoadCommand(MachO.LoadCommands.LC_SYMTAB)
		dysymCmd = self.machoFile.getLoadCommand(MachO.LoadCommands.LC_DYSYMTAB)

		# TODO: handle
		if len(dysymCmd.tocData) or len(dysymCmd.modtabData) or len(dysymCmd.extrefsymsData) or len(dysymCmd.extrelData) or len(dysymCmd.locrelData):
			raise Exception("Unable to handle data!")
		
		# first the entries
		symCmd.symoff = self.dataHead
		self.dataHead += len(symCmd.symbolData)

		dysymCmd.indirectsymoff = self.dataHead
		self.dataHead += len(dysymCmd.indirectsymsData)

		# then the string table
		symCmd.stroff = self.dataHead
		self.dataHead += len(symCmd.stringData)
		pass

	def fixLinkEdit(self) -> None:
		"""Fixes linkedit size.

		Because the LinkEdit segment doesn't have any sections, the method
		processSegment sets the segment's size to 0. The true size of segment
		is from the start of the segment to the end of the file.
		"""

		seg = self.machoFile.getSegment(b"__LINKEDIT\x00")

		size = self.dataHead - seg.fileoff
		seg.vmsize = size
		seg.filesize = size
		pass