import struct
import typing
import logging

from DyldExtractor import MachO
from DyldExtractor import Dyld
from DyldExtractor import Structure

class LinkeditConverter(object):
	"""Rebuilds the linkedit.

	The all the linkedit segments in the dyld are combined
	into one big linkedit segment that is shared by all
	images. This class rebuilds the linkedit segment,
	decaching only the necessary data.
	"""

	exports: typing.List[MachO.TrieEntry]
	localSymEntry: Dyld.dyld_cache_local_symbols_entry

	def __init__(self, machoFile: MachO.MachoFile, dyldFile: Dyld.DyldFile) -> None:
		self.machoFile = machoFile
		self.dyldFile = dyldFile
		pass
	
	def convert(self) -> None:
		self.readExports()
		self.getLocalSymEntry()

		self.buildSymbolTable()
		self.pointerAlignData()
		pass

	def readExports(self) -> None:
		"""
		Gets export symbols
		"""

		self.exports = []

		# try to get exports by LC_DYLD_INFO
		dyldInfo = self.machoFile.getLoadCommand((MachO.LoadCommands.LC_DYLD_INFO, MachO.LoadCommands.LC_DYLD_INFO_ONLY))
		if dyldInfo:
			self.exports = MachO.TrieParser(dyldInfo.exportData).parse()
		else:
			# try to get exports by LC_DYLD_EXPORTS_TRIE
			exportsTrie = self.machoFile.getLoadCommand(MachO.LoadCommands.LC_DYLD_EXPORTS_TRIE)
			if exportsTrie:
				self.exports = MachO.TrieParser(exportsTrie.linkeditData).parse()
			else:
				logging.warning("Unable to get export data.")

		# remove any non ReExport symbols
		reExportDeps = []
		deps = self.machoFile.getLoadCommand(
			(
				MachO.LoadCommands.LC_LOAD_DYLIB,
				MachO.LoadCommands.LC_LOAD_WEAK_DYLIB,
				MachO.LoadCommands.LC_REEXPORT_DYLIB,
				MachO.LoadCommands.LC_LOAD_UPWARD_DYLIB
			),
			multiple=True
		)
		if deps:
			depIndex = 0
			for dep in deps:
				depIndex += 1
				if dep.cmd == MachO.LoadCommands.LC_REEXPORT_DYLIB:
					reExportDeps.append(depIndex)

		def isReExport(entry: MachO.TrieEntry) -> bool:
			if (entry.flags & MachO.Export.EXPORT_SYMBOL_FLAGS_KIND_MASK) != MachO.Export.EXPORT_SYMBOL_FLAGS_KIND_REGULAR:
				return True
			if (entry.flags & MachO.Export.EXPORT_SYMBOL_FLAGS_REEXPORT) == 0:
				return True
			if entry.other in reExportDeps:
				return True
			return False
		
		self.exports = [export for export in self.exports if isReExport(export)]
		pass

	def getLocalSymEntry(self) -> None:
		"""
		Gets the local symbol entry from the
		Dyld header.
		"""

		textSeg = self.machoFile.getSegment(b"__TEXT\x00")
		for entry in self.dyldFile.localSymbolInfo.entries:

			if entry.dylibOffset == textSeg.fileoff:
				self.localSymEntry = entry
				break
		pass

	def calculateEntryCount(self) -> int:
		"""
		Calculates and returns the number of
		entries in the new symbol table.
		"""
		
		symtabCommand: MachO.symtab_command = self.machoFile.getLoadCommand(MachO.LoadCommands.LC_SYMTAB)

		# count local symbols
		entryCount = self.localSymEntry.nlistCount
		
		# count other symbols
		for i in range(0, len(symtabCommand.symbolData), 16):
			nType = struct.unpack_from("<B", symtabCommand.symbolData, i + 4)[0]
			
			# skip any locals in cache
			if (nType & (MachO.NList.N_TYPE | MachO.NList.N_EXT)) == MachO.NList.N_SECT:
				continue
			entryCount += 1

		# add indirect symbols
		dysymtabCommand: MachO.dysymtab_command = self.machoFile.getLoadCommand(MachO.LoadCommands.LC_DYSYMTAB)
		entryCount += dysymtabCommand.nindirectsyms

		# add room for N_INDR symbols for re-exported symbols
		entryCount += len(self.exports)
		return entryCount

	def buildSymbolTable(self) -> None:
		"""
		Rebuilds the symbol table.
		"""
		
		newStrData = b"\x00"
		newSymTab = b""

		symtabCommand: MachO.symtab_command = self.machoFile.getLoadCommand(MachO.LoadCommands.LC_SYMTAB)

		# copy original symbols
		for i in range(0, len(symtabCommand.symbolData), MachO.nlist_64.SIZE):
			symEntry: MachO.nlist_64 = MachO.nlist_64.parseBytes(symtabCommand.symbolData, i)

			# skip local symbols for now
			if (symEntry.n_type & (MachO.NList.N_TYPE | MachO.NList.N_EXT)) == MachO.NList.N_SECT:
				continue

			# get the symbol
			symEnd = symtabCommand.stringData.index(b"\x00", symEntry.n_strx) + 1
			symbol = symtabCommand.stringData[symEntry.n_strx:symEnd]

			# adjust the entry and add it to the new tables
			symEntry.n_strx = len(newStrData)
			newSymTab += symEntry.asBytes()
			newStrData += symbol
		
		# add N_INDR symbols
		for export in self.exports:
			symEntry = MachO.nlist_64()

			symEntry.n_strx = len(newStrData)
			symEntry.n_type = MachO.NList.N_INDR | MachO.NList.N_EXT
			symEntry.n_sect = 0
			symEntry.n_desc = 0
			
			newStrData += export.name

			importName = export.importName if export.importName else export.name
			symEntry.n_value = len(newStrData)

			newStrData += importName
			newSymTab += symEntry.asBytes()
		
		# add the local symbols
		# but first update the load commands
		dysymtabCommand: MachO.dysymtab_command = self.machoFile.getLoadCommand(MachO.LoadCommands.LC_DYSYMTAB)
		dysymtabCommand.ilocalsym = int(len(newSymTab) / MachO.nlist_64.SIZE)
		dysymtabCommand.nlocalsym = self.localSymEntry.nlistCount

		# add the indirect symbols
		indirectSymbolLocalCount = 0
		indirectsymsData = bytearray(dysymtabCommand.indirectsymsData)
		for i in range(0, len(indirectsymsData), 4):
			entryIndex = struct.unpack_from("<I", indirectsymsData, i)[0]
			if entryIndex == 0x80000000:
				indirectSymbolLocalCount += 1
				continue

			entryOff = entryIndex * MachO.nlist_64.SIZE
			entry = MachO.nlist_64.parseBytes(symtabCommand.symbolData, entryOff)

			# get the symbol
			symEnd = symtabCommand.stringData.index(b"\x00", entry.n_strx) + 1
			sym = symtabCommand.stringData[entry.n_strx:symEnd]

			# add the entry
			newEntryIndex = int(len(newSymTab) / MachO.nlist_64.SIZE)
			struct.pack_into("<I", indirectsymsData, i, newEntryIndex)

			entry.n_strx = len(newStrData)
			newSymTab += entry.asBytes()

			# add the symbol
			newStrData += sym
			
		dysymtabCommand.indirectsymsData = bytes(indirectsymsData)

		# copy local symbols
		for i in range(0, self.localSymEntry.nlistCount):
			symOff = (i + self.localSymEntry.nlistStartIndex) * MachO.nlist_64.SIZE
			symEntry = MachO.nlist_64.parseBytes(self.dyldFile.localSymbolInfo.nlistData, symOff)

			localSymEnd = self.dyldFile.localSymbolInfo.stringData.index(b"\x00", symEntry.n_strx) + 1
			localSym = self.dyldFile.localSymbolInfo.stringData[symEntry.n_strx:localSymEnd]

			symEntry.n_strx = len(newStrData)
			newSymTab += symEntry.asBytes()
			newStrData += localSym

		if (self.calculateEntryCount() - indirectSymbolLocalCount) != (len(newSymTab) / MachO.nlist_64.SIZE):
			raise Exception("symbol count miscalculation")

		# set the new data
		symtabCommand.symbolData = newSymTab
		symtabCommand.nsyms = int(len(newSymTab) / MachO.nlist_64.SIZE)
		symtabCommand.stringData = newStrData
		symtabCommand.strsize = len(newStrData)
		pass
	
	def pointerAlignData(self) -> None:
		"""
		Rounds up the size of various sections to the next pointer.
		Assume that the pointer size is 64 bits.
		"""

		funcStarts = self.machoFile.getLoadCommand(MachO.LoadCommands.LC_FUNCTION_STARTS)
		while (len(funcStarts.linkeditData) % 8) != 0:
			funcStarts.linkeditData += b"\x00"
		funcStarts.datasize = len(funcStarts.linkeditData)

		symtab = self.machoFile.getLoadCommand(MachO.LoadCommands.LC_SYMTAB)
		while (len(symtab.stringData) % 8) != 0:
			symtab.stringData += b"\x00"
		symtab.strsize = len(symtab.stringData)
		pass


class MappingInfo(object):

	def __init__(self, mappingInfo, slideInfo) -> None:
		"""
			A storage class for mappings, slide info, and version data
		"""
		super().__init__()

		self.mapping = mappingInfo
		self.slideInfo = slideInfo
		
	def containsAddr(self, addr: int) -> bool:
		"""Check if the address is contained in the mapping info."""

		mappingHighAddr = self.mapping.address + self.mapping.size
		if (addr >= self.mapping.address) and (addr < mappingHighAddr):
			return True
		else:
			return False


class RebaseConverter(object):
	
	"""
		Processes the compressed slide info from the dyld cache and
		creates new rebase info.
	"""

	def __init__(self, machoFile: MachO.MachoFile, dyldFile: Dyld.DyldFile) -> None:
		self.machoFile = machoFile
		self.dyldFile = dyldFile

	def convert(self) -> None:
		"""
			Starts the conversion.
		"""

		# get a list of all the slide info and mappings
		mappingInfoList = []
		if self.dyldFile.header.slideInfoOffset:
			# assume that only the second mapping has slide info
			mappingInfoList.append(MappingInfo(self.dyldFile.mappings[0], None))

			slideInfo = self.getSlideInfo(self.dyldFile.header.slideInfoOffset)
			mapping = self.dyldFile.mappings[1]
			mappingInfoList.append(MappingInfo(mapping, slideInfo))

			# add the rest of the mappings
			[mappingInfoList.append(MappingInfo(mapping, None)) for mapping in self.dyldFile.mappings[2:]]

		
		# see if it uses mappingWithSideOffset
		if self.dyldFile.header.containsField("mappingWithSlideOffset"):
			for i in range(0, self.dyldFile.header.mappingWithSlideCount):
				offset = self.dyldFile.header.mappingWithSlideOffset + (i*Dyld.dyld_cache_mapping_and_slide_info.SIZE)
				mapping = Dyld.dyld_cache_mapping_and_slide_info.parse(self.dyldFile.file, offset)
				
				slideInfo = None
				if mapping.slideInfoFileSize:
					slideInfo = self.getSlideInfo(mapping.slideInfoFileOffset)
				
				mappingInfoList.append(MappingInfo(mapping, slideInfo))

		if len(mappingInfoList) == 0:
			logging.error("Unable to get slide info")
			return

		# Rebase all the segments
		segments = self.machoFile.getLoadCommand(MachO.LoadCommands.LC_SEGMENT_64, multiple=True)
		for seg in segments:
			mappingInfo = next((info for info in mappingInfoList if info.containsAddr(seg.vmaddr)), None)
			
			if not mappingInfo:
				logging.warning(f"Unable to get mapping info for segment: {seg.segname}")
				continue

			if not mappingInfo.slideInfo:
				# There is no slide info for this mapping
				continue

			if mappingInfo.slideInfo.version == 2:
				self.rebaseSegmentV2(seg, mappingInfo)
			elif mappingInfo.slideInfo.version == 3:
				self.rebaseSegmentV3(seg, mappingInfo)
				pass
		pass

	def getSlideInfo(self, slideInfoOffset: int) -> Structure:
		self.dyldFile.file.seek(slideInfoOffset)
		slideInfoVersion = struct.unpack("<I", self.dyldFile.file.read(4))[0]

		if slideInfoVersion == 2:
			return Dyld.dyld_cache_slide_info2.parse(self.dyldFile.file, slideInfoOffset)
		elif slideInfoVersion == 3:
			return Dyld.dyld_cache_slide_info3.parse(self.dyldFile.file, slideInfoOffset)
		else:
			raise Exception(f"Unknown slide info version: {slideInfoVersion}")
		pass

	def rebaseSegmentV2(self, segment: MachO.segment_command_64, mappingInfo: MappingInfo) -> None:
		"""
			Processes the slide info (V2) for one segment.
		"""
		
		if not segment:
			return
		
		dataStart = mappingInfo.mapping.address

		# get the page index which contains the start and end of the segment.
		pageSize = mappingInfo.slideInfo.page_size
		startPageAddr = segment.vmaddr - dataStart
		startPage = int(startPageAddr / pageSize)
		
		endPageAddr = (((segment.vmaddr + segment.vmsize) - dataStart) + pageSize) & ~pageSize
		endPage = int(endPageAddr / pageSize)

		# process each page
		pageStarts = struct.iter_unpack("<H", mappingInfo.slideInfo.pageStartsData)
		pageStarts = [page[0] for page in pageStarts]
		for i in range(startPage, endPage):
			page = pageStarts[i]

			if page == Dyld.Slide.DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE:
				pass
			elif page & Dyld.Slide.DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA:
				raise Exception("Can't handle page extras")
			elif (page & Dyld.Slide.DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) == 0:
				pageOffset = (i * pageSize) + mappingInfo.mapping.fileOffset
				self.rebasePageV2(pageOffset, page * 4, segment, mappingInfo.slideInfo)
			else:
				raise Exception("Unknown page type")
		pass

	def rebaseSegmentV3(self, segment: MachO.segment_command_64, mappingInfo: MappingInfo) -> None:
		"""
			Processes the slide info (V3) for one segment.
		"""

		if not segment:
			return
		
		dataStart = mappingInfo.mapping.address

		# get the page index which contains the start and end of the segment.
		pageSize = mappingInfo.slideInfo.page_size
		startPageAddr = segment.vmaddr - dataStart
		startPage = int(startPageAddr / pageSize)
		
		endPageAddr = (((segment.vmaddr + segment.vmsize) - dataStart) + pageSize) & ~pageSize
		endPage = int(endPageAddr / pageSize)

		# process each page
		pageStarts = struct.iter_unpack("<H", mappingInfo.slideInfo.pageStartsData)
		pageStarts = [page[0] for page in pageStarts]
		for i in range(startPage, endPage):
			page = pageStarts[i]
			
			if page == Dyld.Slide.DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE:
				pass
			else:
				pageOffset = (i * pageSize) + mappingInfo.mapping.fileOffset
				self.rebasePageV3(pageOffset, page, segment, mappingInfo.slideInfo)
				pass
		pass

	def rebasePageV2(self, pageOffset: int, firstRebaseOffset: int, segment: MachO.segment_command_64, slideInfo: Dyld.dyld_cache_slide_info2) -> None:
		"""
			processes the rebase infomation (V2) in a page

			### parameters
			pageOffset: int
				
				The file offset of the page.

			firstRebaseOffset: int

				The offset from the start of the page to the first
				rebase location.
			
			segment: segment_command_64

				The segment to rebase.
			
		"""

		deltaMask = slideInfo.delta_mask
		valueMask = ~deltaMask
		valueAdd = slideInfo.value_add

		# basically __builtin_ctzll(deltaMask) - 2;
		deltaShift = "{0:b}".format(deltaMask)
		deltaShift = len(deltaShift) - len(deltaShift.rstrip("0"))
		deltaShift = deltaShift - 2

		delta = 1

		rebaseOffset = firstRebaseOffset
		while delta != 0:
			realLoc = pageOffset + rebaseOffset

			self.dyldFile.file.seek(realLoc)

			rawValueBytes = self.dyldFile.file.read(8)
			rawValue = struct.unpack("<Q", rawValueBytes)[0]

			delta = (rawValue & deltaMask) >> deltaShift
			value = rawValue & valueMask
			if value:
				value += valueAdd

			# if the location is within the segment, adjust the data
			if realLoc >= segment.fileoff and realLoc < (segment.fileoff + segment.filesize):
				self.slideLocation(realLoc, value, segment)
			
			rebaseOffset += delta
	
	def rebasePageV3(self, pageOffset: int, delta: int, segment: MachO.segment_command_64, slideInfo: Dyld.dyld_cache_slide_info3) -> None:
		"""Process rebase info (V3) for a page.

		args:
			pageOffset: the file offset to the target page.
			delta: the offset to the first rebase location in the page.
			segment: the segment to rebase.
		"""

		loc = pageOffset
		while True:
			loc += delta
			locInfo = Dyld.dyld_cache_slide_pointer3.parse(self.dyldFile.file, loc)

			delta = locInfo.plain.offsetToNextPointer

			# check if the segment contains the address
			if not (loc >= segment.fileoff and loc < (segment.fileoff + segment.filesize)):
				if delta == 0:
					break

				continue

			# calculate the new value
			newValue = None
			if locInfo.auth.authenticated:
				newValue = locInfo.auth.offsetFromSharedCacheBase + slideInfo.auth_value_add
			else:
				value51 = locInfo.plain.pointerValue
				top8Bits = value51 & 0x0007F80000000000
				bottom43Bits = value51 & 0x000007FFFFFFFFFF
				newValue = ( top8Bits << 13 ) | bottom43Bits

			self.slideLocation(loc, newValue, segment)
			
			if delta == 0:
				break
		pass

	def slideLocation(self, fileOffset: int, value: int, segment: MachO.segment_command_64) -> None:
		"""
			Sets the value at the file offset.
		"""

		# find the section with the fileOffset
		containingSect = None
		for section in segment.sections:
			if fileOffset >= section.offset and fileOffset < (section.offset + section.size):
				containingSect = section
				break
		
		if not containingSect:
			raise Exception("Unable to find section")

		# write it
		sectionOff = fileOffset - containingSect.offset

		sectionData = containingSect.sectionData[0:sectionOff]
		sectionData += struct.pack("<Q", value)
		sectionData += containingSect.sectionData[sectionOff+8:]
		containingSect.sectionData = sectionData