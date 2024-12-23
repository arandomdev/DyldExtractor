from dataclasses import dataclass
from typing import List

from DyldExtractor.extraction_context import ExtractionContext
from DyldExtractor.macho.macho_context import MachOContext
from DyldExtractor.file_context import FileContext

from DyldExtractor.macho.macho_structs import (
	linkedit_data_command,
	dyld_info_command,
	symtab_command,
	dysymtab_command,
	routines_command_64,
)


_PAGE_SIZE = 0x4000


@dataclass
class WriteProcedure(object):
	writeOffset: int
	"""The offset to write to."""
	readOffset: int
	"""The offset to read from the fileCtx."""
	size: int
	"""The number of bytes to write."""
	fileCtx: FileContext
	"""The file to read from."""


class BytesFileContext(object):
	"""Create a FileContext like object for bytes"""

	def __init__(self, buffer: bytes) -> None:
		super().__init__()
		self._buffer = buffer
		pass

	def getBytes(self, offset: int, size: int) -> bytes:
		return self._buffer[offset:offset + size]
	pass


def _updateLinkEdit(
	machoCtx: MachOContext,
	shiftDelta: int
) -> None:
	"""Adjust file offsets for LinkEdit LoadCommands.
	"""

	for lc in machoCtx.loadCommands:
		if isinstance(lc, linkedit_data_command):
			lc.dataoff += shiftDelta if lc.dataoff else 0

		elif isinstance(lc, dyld_info_command):
			lc.rebase_off += shiftDelta if lc.rebase_off else 0
			lc.bind_off += shiftDelta if lc.bind_off else 0
			lc.weak_bind_off += shiftDelta if lc.weak_bind_off else 0
			lc.lazy_bind_off += shiftDelta if lc.lazy_bind_off else 0
			lc.export_off += shiftDelta if lc.export_off else 0

		elif isinstance(lc, symtab_command):
			lc.symoff += shiftDelta if lc.symoff else 0
			lc.stroff += shiftDelta if lc.stroff else 0

		elif isinstance(lc, dysymtab_command):
			lc.tocoff += shiftDelta if lc.tocoff else 0
			lc.modtaboff += shiftDelta if lc.modtaboff else 0
			lc.extrefsymoff += shiftDelta if lc.extrefsymoff else 0
			lc.indirectsymoff += shiftDelta if lc.indirectsymoff else 0
			lc.extreloff += shiftDelta if lc.extreloff else 0
			lc.locreloff += shiftDelta if lc.locreloff else 0

		elif isinstance(lc, routines_command_64):
			lc.init_address += shiftDelta if lc.init_address else 0


def optimizeOffsets(extractionCtx: ExtractionContext) -> List[WriteProcedure]:
	"""Adjusts file offsets.

		MachO files in the Dyld Shared Cache are split up, which causes
	decached files to have really weird offsets. This fixes that.

	Args:
		machoCtx: A writable MachOContext.

	Returns:
		A list of WriteProcedures to aid in writing to a decached file.
	"""

	extractionCtx.statusBar.update(unit="Optimize Offsets")

	# The data in a MachO are defined by the segment load commands,
	# This includes the LinkEdit and MachO header
	machoCtx = extractionCtx.machoCtx
	dyldCtx = extractionCtx.dyldCtx

	# first change all the offset fields and record the writes
	writeProcedures = []
	dataHead = 0

	for segname, segment in machoCtx.segments.items():
		shiftDelta = dataHead - segment.seg.fileoff

		if segname == extractionCtx.EXTRA_SEGMENT_NAME:
			procedure = WriteProcedure(
				segment.seg.fileoff + shiftDelta,
				0,
				segment.seg.filesize,
				BytesFileContext(extractionCtx.extraSegmentData)
			)
			pass
		else:
			procedure = WriteProcedure(
				segment.seg.fileoff + shiftDelta,
				dyldCtx.convertAddr(segment.seg.vmaddr)[0],
				segment.seg.filesize,
				machoCtx.ctxForAddr(segment.seg.vmaddr)
			)
			pass
		writeProcedures.append(procedure)

		if segname == b"__LINKEDIT":
			_updateLinkEdit(machoCtx, shiftDelta)
			pass

		# Change the offsets for the segment and section structures
		segment.seg.fileoff += shiftDelta
		for sect in segment.sects.values():
			sect.offset = max(sect.offset + shiftDelta, 0)
			pass

		# update the data head to the next page aligned offset
		dataHead += segment.seg.filesize
		dataHead += _PAGE_SIZE - (dataHead % _PAGE_SIZE)
		pass

	return writeProcedures
