from io import BufferedReader

from DyldExtractor.MachO.MachoFile import MachoFile
from DyldExtractor.MachO.MachoStructs import LoadCommands


class Writer(object):
	"""
	Writes a MachO file.
	"""

	outFile: BufferedReader

	def __init__(self, machoFile: MachoFile) -> None:
		self.machoFile = machoFile

	def writeToPath(self, path: str) -> None:
		"""Writes the macho file to the path.

		Parameters
		----------
			path : str
				The file path.
		"""

		with open(path, mode="wb") as self.outFile:
			# write the header and load commands
			self.outFile.write(self.machoFile.machHeader.asBytes())

			# write all the load commands
			cmdData = b""
			for cmd in self.machoFile.loadCommands:
				cmdData += cmd.asBytes()

				if cmd.cmd == LoadCommands.LC_SEGMENT_64:
					for sect in cmd.sections:
						cmdData += sect.asBytes()
			self.outFile.write(cmdData)

			self.writeLoadcommands()
		pass

	def writeLoadcommands(self) -> None:
		"""
		Writes the data.
		"""

		for command in self.machoFile.loadCommands:

			if command.cmd == LoadCommands.LC_SEGMENT_64:
				
				for sect in command.sections:
					if sect.offset:
						self.outFile.seek(sect.offset)
						self.outFile.write(sect.sectionData)
				pass
			
			elif (
				command.cmd == LoadCommands.LC_DYLD_INFO
				or command.cmd == LoadCommands.LC_DYLD_INFO_ONLY
			):
				if command.rebase_off:
					self.outFile.seek(command.rebase_off)
					self.outFile.write(command.rebaseData)
				if command.bind_off:
					self.outFile.seek(command.bind_off)
					self.outFile.write(command.bindData)
				if command.weak_bind_off:
					self.outFile.seek(command.weak_bind_off)
					self.outFile.write(command.weak_bindData)
				if command.lazy_bind_off:
					self.outFile.seek(command.lazy_bind_off)
					self.outFile.write(command.lazy_bindData)
				if command.export_off:
					self.outFile.seek(command.export_off)
					self.outFile.write(command.exportData)
				pass

			elif (
				command.cmd == LoadCommands.LC_FUNCTION_STARTS
				or command.cmd == LoadCommands.LC_DATA_IN_CODE
				or command.cmd == LoadCommands.LC_DYLD_EXPORTS_TRIE
			):
				self.outFile.seek(command.dataoff)
				self.outFile.write(command.linkeditData)
				pass

			elif command.cmd == LoadCommands.LC_SYMTAB:
				self.outFile.seek(command.symoff)
				self.outFile.write(command.symbolData)
				self.outFile.seek(command.stroff)
				self.outFile.write(command.stringData)
				pass

			elif command.cmd == LoadCommands.LC_DYSYMTAB:	
				if command.tocoff:
					self.outFile.seek(command.tocoff)
					self.outFile.write(command.tocData)
				if command.modtaboff:
					self.outFile.seek(command.modtaboff)
					self.outFile.write(command.modtabData)
				if command.extrefsymoff:
					self.outFile.seek(command.extrefsymoff)
					self.outFile.write(command.extrefsymsData)
				if command.indirectsymoff:
					self.outFile.seek(command.indirectsymoff)
					self.outFile.write(command.indirectsymsData)
				if command.extreloff:
					self.outFile.seek(command.extreloff)
					self.outFile.write(command.extrelData)
				if command.locreloff:
					self.outFile.seek(command.locreloff)
					self.outFile.write(command.locrelData)
				pass

			elif (
				command.cmd == LoadCommands.LC_BUILD_VERSION
				or command.cmd == LoadCommands.LC_ID_DYLIB
				or command.cmd == LoadCommands.LC_LOAD_DYLIB
				or command.cmd == LoadCommands.LC_REEXPORT_DYLIB
				or command.cmd == LoadCommands.LC_LOAD_WEAK_DYLIB
				or command.cmd == LoadCommands.LC_LOAD_UPWARD_DYLIB
				or command.cmd == LoadCommands.LC_UUID
				or command.cmd == LoadCommands.LC_SOURCE_VERSION
				or command.cmd == LoadCommands.LC_SUB_FRAMEWORK
				or command.cmd == LoadCommands.LC_SUB_CLIENT
				or command.cmd == LoadCommands.LC_ROUTINES_64
				or command.cmd == LoadCommands.LC_ENCRYPTION_INFO_64
				or command.cmd == LoadCommands.LC_RPATH
				or command.cmd == LoadCommands.LC_VERSION_MIN_MACOSX
				or command.cmd == LoadCommands.LC_VERSION_MIN_IPHONEOS
				or command.cmd == LoadCommands.LC_VERSION_MIN_WATCHOS
				or command.cmd == LoadCommands.LC_VERSION_MIN_TVOS
			):
				pass

			else:
				raise Exception("Unknown load command: " + LoadCommands(command.cmd).name)

		pass