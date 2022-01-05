import struct
from typing import (
	Union,
	List,
	Dict,
	Tuple,
	BinaryIO,
	Protocol
)

from DyldExtractor.file_context import FileContext
from DyldExtractor.macho.segment_context import SegmentContext

from DyldExtractor.macho.macho_structs import (
	LoadCommandMap,
	LoadCommands,
	load_command,
	UnknownLoadCommand,
	mach_header_64,
	segment_command_64
)


class MappingInfo(Protocol):
	address: int
	size: int


class MachOContext(FileContext):

	loadCommands: List[load_command]

	segments: Dict[bytes, SegmentContext]
	segmentsI: List[SegmentContext]

	def __init__(
		self,
		fileObject: BinaryIO,
		offset: int = 0,
		copyMode: bool = False
	) -> None:
		"""A wrapper around a MachO file.

		Provides convenient methods and attributes for a given MachO file.

		Args:
			file: The macho file.
			offset: The offset to the header in the file.
		"""

		super().__init__(fileObject, copyMode=copyMode)
		self.fileOffset = offset

		self.header = mach_header_64(self.file, self.fileOffset)
		self._mappings: List[Tuple[MappingInfo, "MachOContext"]] = []

		# check to make sure the MachO file is 64 bit
		magic = self.header.magic
		if magic == 0xfeedface or magic == 0xcefaedfe:
			raise Exception("MachOContext doesn't support 32bit files!")

		self._parseLoadCommands()
		pass

	def getLoadCommand(
		self,
		cmdFilter: Tuple[LoadCommands],
		multiple: bool = False
	) -> Union[load_command, Tuple[load_command]]:
		"""Retreive a load command with its command ID

		Args:
			filter: The command to filter by.
			multiple: Optional; To get multiple results instead of the first.

		Returns:
			If the command is not found, None is returned. If one was found it will
			return the first match. If multiple is set to True, it will return a list
			of matches.
		"""

		matches = []
		for loadCommand in self.loadCommands:
			if loadCommand.cmd in cmdFilter:
				if not multiple:
					return loadCommand
				else:
					matches.append(loadCommand)

		if len(matches) == 0:
			return None

		return matches

	def containsAddr(self, address: int) -> bool:
		"""Check if the address is contained in the MachO file.

		Args:
			address: the VM address to check.

		Returns:
			Whether or not the address is contained in the segments
			of this MachO file.
		"""

		for segment in self.segmentsI:
			seg = segment.seg
			lowBound = seg.vmaddr
			highBound = lowBound + seg.vmsize

			if address >= lowBound and address < highBound:
				return True

		return False

	def _parseLoadCommands(self) -> None:
		"""Parse the load commands

		Parse the load commands and set the loadCommands attribute.
		"""
		self.header = mach_header_64(self.file, self.fileOffset)

		self.loadCommands = []

		self.segments = {}
		self.segmentsI = []

		cmdOff = len(self.header) + self.fileOffset
		for _ in range(self.header.ncmds):
			self.file.seek(cmdOff)
			cmd = struct.unpack("<I", self.file.read(4))[0]

			command = LoadCommandMap.get(cmd, UnknownLoadCommand)
			if command == UnknownLoadCommand:
				raise Exception(f"Unknown LoadCommand: {hex(cmd)}")

			command = command(self.file, cmdOff)

			cmdOff += command.cmdsize
			self.loadCommands.append(command)

			# populate the segments at this point too
			if isinstance(command, segment_command_64):
				segCtx = SegmentContext(self.file, command)

				self.segments[command.segname] = segCtx
				self.segmentsI.append(segCtx)
				pass
			pass
		pass

	def reloadLoadCommands(self) -> None:
		"""Reload the load commands.

		Read the header and load commands with the
		same file and offset.
		"""

		self._parseLoadCommands()
		pass

	def addSubfiles(
		self,
		mainFileMap: MappingInfo,
		subFilesAndMaps: List[Tuple[MappingInfo, "MachOContext"]]
	) -> None:
		"""Add sub files.

		Used when the data to describe a MachO file is split into multiple
		files, each file needs to have mapping info.

		Args:
			mainFileMap: Mapping info for the file that contains the header.
			subFilesAndMaps: A list of tuples that contain the sub file context
				and the mapping info.
		"""
		self._mappings.append((mainFileMap, self))
		self._mappings.extend(subFilesAndMaps)
		pass

	def ctxForAddr(self, vmaddr: int) -> "MachOContext":
		"""Get the file context that contains the address.

		If there are no sub files added, this just returns the main
		file context. If the file cannot be found, this returns None.
		"""

		if not self._mappings:
			return self

		for mapping, ctx in self._mappings:
			lowBound = mapping.address
			highBound = mapping.address + mapping.size

			if vmaddr >= lowBound and vmaddr < highBound:
				return ctx

		# didn't find the address in any mappings...
		return None
