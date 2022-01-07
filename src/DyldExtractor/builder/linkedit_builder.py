from typing import (
	Any,
	Callable,
	Generic,
	List,
	TypeVar
)

from DyldExtractor.macho.macho_context import MachOContext
from DyldExtractor.file_context import FileContext

from DyldExtractor.macho.macho_structs import (
	LoadCommands,
	dyld_info_command,
	dysymtab_command,
	linkedit_data_command,
	load_command,
	symtab_command,
	nlist_64
)


_C = TypeVar("_C", bound=load_command)


class LoadCommandData(Generic[_C]):

	def __init__(self, command: _C, source: FileContext) -> None:
		super().__init__()

		self.dataFields: List[str] = []
		"""List of data fields that need data loading."""

		self.command = command
		self.source = source

		self.updaters: List[Callable[[int], bytes]] = []
		"""Updater Function, (newOffset) -> dataSize"""

		self._loadingData = False
		self._fieldStorage = {}
		pass

	def loadData(self) -> None:
		...

	def __getattr__(self, __name: str) -> Any:
		# load data
		if __name in super().__getattribute__("dataFields"):
			if not super().__getattribute__("_loadingData"):
				super().__setattr__("_loadingData", True)

				# Fill undefined storage fields with none
				storage = super().__getattribute__("_fieldStorage")
				for name in super().__getattribute__("dataFields"):
					if name not in storage:
						storage[name] = None
						pass
					pass
				super().__getattribute__("loadData")()

				super().__setattr__("_loadingData", False)
				pass

			return super().__getattribute__("_fieldStorage")[__name]
		else:
			return super().__getattribute__(__name)

	def __setattr__(self, __name: str, __value: Any) -> None:
		if (
			__name != "dataFields"
			and __name in super().__getattribute__("dataFields")
		):
			super().__getattribute__("_fieldStorage")[__name] = __value
			pass
		else:
			super().__setattr__(__name, __value)
			pass
		pass
	pass


class SymtabCommandData(LoadCommandData[symtab_command]):

	symbols: bytearray
	strings: bytearray

	def __init__(self, command: symtab_command, source: FileContext) -> None:
		super().__init__(command, source)

		self.updaters = [
			self._symbolsUpdater,
			self.stringsUpdater
		]
		self.dataFields = [
			"symbols",
			"strings"
		]
		pass

	def loadData(self) -> None:
		if self.symbols is None:
			self.symbols = bytearray(
				self.source.getBytes(
					self.command.symoff,
					self.command.nsyms * nlist_64.SIZE
				)
			)
			pass

		if self.strings is None:
			self.strings = bytearray(
				self.source.getBytes(
					self.command.stroff,
					self.command.strsize
				)
			)
			pass
		pass

	def _symbolsUpdater(self, newOffset: int) -> bytes:
		self.command.nsyms = int(len(self.symbols) / nlist_64.SIZE)
		self.command.symoff = newOffset if self.command.nsyms else 0
		return self.symbols

	def stringsUpdater(self, newOffset: int) -> bytes:
		self.command.strsize = len(self.strings)
		self.command.stroff = newOffset if self.command.strsize else 0
		return self.strings
	pass


class DysymtabCommandData(LoadCommandData[dysymtab_command]):

	indirectSyms: bytearray

	def __init__(self, command: dysymtab_command, source: FileContext) -> None:
		super().__init__(command, source)

		self.updaters = [
			self.indirectSymUpdater
		]
		self.dataFields = [
			"indirectSyms"
		]
		pass

	def loadData(self) -> None:
		if self.indirectSyms is None:
			self.indirectSyms = bytearray(
				self.source.getBytes(
					self.command.indirectsymoff,
					self.command.nindirectsyms * 4
				)
			)
			pass
		pass

	def indirectSymUpdater(self, newOffset: int) -> bytes:
		self.command.nindirectsyms = int(len(self.indirectSyms) / 4)
		self.command.indirectsymoff = newOffset if self.command.nindirectsyms else 0
		return self.indirectSyms
	pass


class LinkeditDataCommandData(LoadCommandData[linkedit_data_command]):

	data: bytearray

	def __init__(
		self,
		command: linkedit_data_command,
		source: FileContext
	) -> None:
		super().__init__(command, source)

		self.updaters = [
			self._dataUpdater
		]
		self.dataFields = [
			"data"
		]
		pass

	def loadData(self) -> None:
		if self.data is None:
			self.data = bytearray(
				self.source.getBytes(
					self.command.dataoff,
					self.command.datasize
				)
			)
			pass
		pass

	def _dataUpdater(self, newOffset: int) -> bytes:
		self.command.datasize = len(self.data)
		self.command.dataoff = newOffset  # even if len is 0
		return self.data
	pass


class DyldInfoCommandData(LoadCommandData[dyld_info_command]):

	rebaseData: bytearray
	bindData: bytearray
	weakBindData: bytearray
	lazyBindData: bytearray
	exportData: bytearray

	def __init__(
		self,
		command: dyld_info_command,
		source: FileContext
	) -> None:
		super().__init__(command, source)

		self.updaters = [
			self._rebaseUpdater,
			self._bindUpdater,
			self._weakBindUpdater,
			self._lazyBindUpdater,
			self._exportUpdater
		]
		self.dataFields = [
			"rebaseData",
			"bindData",
			"weakBindData",
			"lazyBindData",
			"exportData"
		]
		pass

	def loadData(self) -> None:
		if self.rebaseData is None:
			self.rebaseData = bytearray(
				self.source.getBytes(
					self.command.rebase_off,
					self.command.rebase_size
				)
			)
			pass

		if self.bindData is None:
			self.bindData = bytearray(
				self.source.getBytes(
					self.command.bind_off,
					self.command.bind_size
				)
			)
			pass

		if self.weakBindData is None:
			self.weakBindData = bytearray(
				self.source.getBytes(
					self.command.weak_bind_off,
					self.command.weak_bind_size
				)
			)
			pass

		if self.lazyBindData is None:
			self.lazyBindData = bytearray(
				self.source.getBytes(
					self.command.lazy_bind_off,
					self.command.lazy_bind_size
				)
			)
			pass

		if self.exportData is None:
			self.exportData = bytearray(
				self.source.getBytes(
					self.command.export_off,
					self.command.export_size
				)
			)
			pass
		pass

	def _rebaseUpdater(self, newOffset: int) -> bytes:
		self.command.rebase_size = len(self.rebaseData)
		self.command.rebase_off = newOffset if self.command.rebase_size else 0
		return self.rebaseData

	def _bindUpdater(self, newOffset: int) -> bytes:
		self.command.bind_size = len(self.bindData)
		self.command.bind_off = newOffset if self.command.bind_size else 0
		return self.bindData

	def _weakBindUpdater(self, newOffset: int) -> bytes:
		self.command.weak_bind_size = len(self.weakBindData)
		self.command.weak_bind_off = newOffset if self.command.weak_bind_size else 0
		return self.weakBindData

	def _lazyBindUpdater(self, newOffset: int) -> bytes:
		self.command.lazy_bind_size = len(self.lazyBindData)
		self.command.lazy_bind_off = newOffset if self.command.lazy_bind_size else 0
		return self.lazyBindData

	def _exportUpdater(self, newOffset: int) -> bytes:
		self.command.export_size = len(self.exportData)
		self.command.export_off = newOffset if self.command.export_size else 0
		return self.exportData


class LinkeditBuilder(object):

	def __init__(self, machoCtx: MachOContext) -> None:
		"""Builds the linkedit segment.

		Args:
			machoCtx: A writable MachOContext to manage.
		"""

		super().__init__()
		self._machoCtx = machoCtx
		self._linkeditCtx = machoCtx.ctxForAddr(
			self._machoCtx.segments[b"__LINKEDIT"].seg.vmaddr
		)

		self._loadCommands: List[LoadCommandData] = []

		self.symtabData = None
		self.dysymtabData = None
		self.dyldInfoData = None

		self._processLoadCommands()
		pass

	def _processLoadCommands(self) -> None:
		for lc in self._machoCtx.loadCommands:
			lcCmd = lc.cmd

			if lcCmd == LoadCommands.LC_SYMTAB:
				self.symtabData = SymtabCommandData(lc, self._linkeditCtx)
				self._loadCommands.append(self.symtabData)
				pass
			elif lcCmd == LoadCommands.LC_DYSYMTAB:
				self.dysymtabData = DysymtabCommandData(lc, self._linkeditCtx)
				self._loadCommands.append(self.dysymtabData)
				pass
			elif lcCmd in (
				LoadCommands.LC_CODE_SIGNATURE,
				LoadCommands.LC_SEGMENT_SPLIT_INFO,
				LoadCommands.LC_FUNCTION_STARTS,
				LoadCommands.LC_DATA_IN_CODE,
				LoadCommands.LC_DYLIB_CODE_SIGN_DRS,
				LoadCommands.LC_LINKER_OPTION,
				LoadCommands.LC_LINKER_OPTIMIZATION_HINT,
				LoadCommands.LC_DYLD_EXPORTS_TRIE,
				LoadCommands.LC_DYLD_CHAINED_FIXUPS
			):
				self._loadCommands.append(LinkeditDataCommandData(lc, self._linkeditCtx))
				pass
			elif (
				lcCmd == LoadCommands.LC_DYLD_INFO
				or lcCmd == LoadCommands.LC_DYLD_INFO_ONLY
			):
				self.dyldInfoData = DyldInfoCommandData(lc, self._linkeditCtx)
				self._loadCommands.append(self.dyldInfoData)
				pass

			elif lcCmd in (
				LoadCommands.LC_LOAD_DYLIB,
				LoadCommands.LC_ID_DYLIB,
				LoadCommands.LC_LOAD_DYLINKER,
				LoadCommands.LC_ID_DYLINKER,
				LoadCommands.LC_SUB_FRAMEWORK,
				LoadCommands.LC_SUB_UMBRELLA,
				LoadCommands.LC_SUB_CLIENT,
				LoadCommands.LC_SUB_LIBRARY,
				LoadCommands.LC_LOAD_WEAK_DYLIB,
				LoadCommands.LC_SEGMENT_64,
				LoadCommands.LC_ROUTINES_64,
				LoadCommands.LC_UUID,
				LoadCommands.LC_RPATH,
				LoadCommands.LC_REEXPORT_DYLIB,
				LoadCommands.LC_LAZY_LOAD_DYLIB,
				LoadCommands.LC_LOAD_UPWARD_DYLIB,
				LoadCommands.LC_VERSION_MIN_MACOSX,
				LoadCommands.LC_VERSION_MIN_IPHONEOS,
				LoadCommands.LC_DYLD_ENVIRONMENT,
				LoadCommands.LC_MAIN,
				LoadCommands.LC_SOURCE_VERSION,
				LoadCommands.LC_ENCRYPTION_INFO_64,
				LoadCommands.LC_VERSION_MIN_TVOS,
				LoadCommands.LC_VERSION_MIN_WATCHOS,
				LoadCommands.LC_BUILD_VERSION
			):
				pass

			else:
				raise TypeError(f"Unknown load command: {lc}")
			pass
		pass

	def build(self, newOffset: int) -> None:
		"""Rebuild the linkedit segment

		Rebuild so that all the data is in one continuous range.
		"""

		newLinkedit = bytearray()
		dataHead = newOffset

		def ptrAlign(data: bytes) -> bytes:
			fill = b"\x00" * (len(data) % 8)
			return data + fill

		# update the strings after the symbols and indirect symbols
		updaters = []
		for lc in self._loadCommands:
			updaters.extend(lc.updaters)
			pass

		updaters.remove(self.symtabData.stringsUpdater)
		updaters.insert(
			updaters.index(self.dysymtabData.indirectSymUpdater) + 1,
			self.symtabData.stringsUpdater
		)

		for updater in updaters:
			data = ptrAlign(updater(dataHead))
			newLinkedit.extend(data)
			dataHead += len(data)
			pass

		self._linkeditCtx.writeBytes(newOffset, newLinkedit)
		linkeditSeg = self._machoCtx.segments[b"__LINKEDIT"].seg
		linkeditSeg.fileoff = newOffset
		linkeditSeg.filesize = len(newLinkedit)
		linkeditSeg.vmsize = len(newLinkedit)
		pass
	pass
