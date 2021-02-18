from __future__ import annotations

import struct
import copy

from typing import List, Union, Tuple
from io import BufferedReader

from DyldExtractor.MachO.MachoStructs import *


class MachoFile(object):
	"""Wraps and provides info about a macho file.

	Attributes
	----------
		machHeader: mach_header_64

		loadCommands: List[load_command]
	"""

	machHeader: mach_header_64 = None
	loadCommands: List[load_command]

	@classmethod
	def parse(cls, buffer: BufferedReader, fileOffset: int, loadData: bool = True) -> MachoFile:
		inst = cls()

		inst.machHeader = mach_header_64.parse(buffer, fileOffset)
		inst.loadCommands = []

		# get parse all the load commands
		currentOff = fileOffset + mach_header_64.SIZE
		for _ in range(inst.machHeader.ncmds):
			buffer.seek(currentOff)
			cmd, cmdsize = struct.unpack("<II", buffer.read(8))

			command = None
			if cmd == LoadCommands.LC_SEGMENT_64:
				command = segment_command_64
			elif cmd == LoadCommands.LC_DYLD_INFO or cmd == LoadCommands.LC_DYLD_INFO_ONLY:
				command = dyld_info_command
			elif cmd == LoadCommands.LC_SYMTAB:
				command = symtab_command
			elif cmd == LoadCommands.LC_DYSYMTAB:
				command = dysymtab_command
			elif cmd == LoadCommands.LC_CODE_SIGNATURE or cmd == LoadCommands.LC_SEGMENT_SPLIT_INFO or cmd == LoadCommands.LC_FUNCTION_STARTS or cmd == LoadCommands.LC_DATA_IN_CODE or cmd == LoadCommands.LC_DYLIB_CODE_SIGN_DRS or cmd == LoadCommands.LC_LINKER_OPTIMIZATION_HINT or cmd == LoadCommands.LC_DYLD_EXPORTS_TRIE or cmd == LoadCommands.LC_DYLD_CHAINED_FIXUPS:
				command = linkedit_data_command
			elif cmd == LoadCommands.LC_ID_DYLIB or cmd == LoadCommands.LC_LOAD_DYLIB or cmd == LoadCommands.LC_LOAD_WEAK_DYLIB or cmd == LoadCommands.LC_REEXPORT_DYLIB or cmd == LoadCommands.LC_LOAD_UPWARD_DYLIB:
				command = dylib_command
			elif cmd == LoadCommands.LC_UUID:
				command = uuid_command
			elif cmd == LoadCommands.LC_BUILD_VERSION:
				command = build_version_command
			elif cmd == LoadCommands.LC_SOURCE_VERSION:
				command = source_version_command
			elif cmd == LoadCommands.LC_ENCRYPTION_INFO_64:
				command = encryption_info_command_64
			elif cmd == LoadCommands.LC_RPATH:
				command = rpath_command
			elif cmd == LoadCommands.LC_SUB_FRAMEWORK:
				command = sub_framework_command
			elif cmd == LoadCommands.LC_SUB_CLIENT:
				command = sub_client_command
			elif cmd == LoadCommands.LC_ROUTINES_64:
				command = routines_command_64
			else:
				raise Exception("Unknown Loadcommand: " + LoadCommands(cmd).name)

			inst.loadCommands.append(command.parse(buffer, currentOff, loadData=loadData))
			currentOff += cmdsize
		
		return inst
	
	def __deepcopy__(self, memo):
		inst = type(self)()
		
		inst.machHeader = copy.deepcopy(self.machHeader)
		inst.loadCommands = copy.deepcopy(self.loadCommands)
		return inst
	
	def getLoadCommand(self, cmd: Union[int, Tuple[int]], multiple: bool = False) -> Union[load_command, List[load_command]]:
		"""Gets a load command.

		This will return None if there are no matches.

		Parameters
		----------
			cmd : Union[int, Tuple[int]]
				A command identifier or a tuple of command identifiers.
			multiple : bool, optional
				If True, this method could return a list of load commands,
				otherwise it will return the first load command that 
				matches the identifiers.

		Returns
		-------
			Union[load_command, List[load_command]]
				A load command or a list of load commands
		"""

		if isinstance(cmd, int):
			cmd = (cmd,)

		matched = []
		for command in self.loadCommands:
			if command.cmd in cmd:
				
				if multiple:
					matched.append(command)
				else:
					return command

		return matched if len(matched) else None
	
	def getSegment(self, segname: bytes, sectname: bytes = None) -> Union[segment_command_64, Tuple[segment_command_64, section_64]]:
		"""Get a segment and section.

		Parameters
		----------
			segname : bytes
				The name of the segment, should be null terminated it less than
				16 bytes.
			sectname : bytes, optional
				The name of a section, also null terminated.

		Returns
		-------
			Union[segment_command_64, Tuple[segment_command_64, section_64]]
				A segment or a segment and section, depending on if a section
				name was provided.
		"""

		targetSeg = None
		targetSect = None

		for segment in self.getLoadCommand(LoadCommands.LC_SEGMENT_64, multiple=True):
			if segname in segment.segname:
				targetSeg = segment

				if sectname:
					for section in segment.sections:
						if sectname in section.sectname:
							targetSect = section
							break
		
		return (targetSeg, targetSect) if sectname else targetSeg
	
	def containsAddr(self, vmaddr: int) -> bool:
		"""Returns wether or not a VMAddress is contained in a segment.

		Parameters
		----------
			vmaddr : int
				The VMAddr.

		Returns
		-------
			bool
		"""

		segments = self.getLoadCommand(LoadCommands.LC_SEGMENT_64, multiple=True)
		
		for seg in segments:
			if vmaddr >= seg.vmaddr and vmaddr < seg.vmaddr + seg.vmsize:
				return True
		return False
	
	def segmentForAddr(self, vmaddr: int) -> Tuple[segment_command_64, section_64]:
		"""Gets the segment and section that contains the VMAddress.

		Parameters
		----------
			vmaddr : int
				The VMAddress.

		Returns
		-------
			Tuple[segment_command_64, section_64]
		"""

		segments = self.getLoadCommand(LoadCommands.LC_SEGMENT_64, multiple=True)
		
		for seg in segments:
			# check if the segment has the address
			if vmaddr >= seg.vmaddr and vmaddr < seg.vmaddr + seg.vmsize:
				
				for sect in seg.sections:
					# Check if the section has the address
					if vmaddr >= sect.addr and vmaddr < sect.addr + sect.size:
						return (seg, sect)
		return None