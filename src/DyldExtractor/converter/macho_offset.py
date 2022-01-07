from dataclasses import dataclass
from typing import List

from DyldExtractor.builder.linkedit_builder import LinkeditBuilder
from DyldExtractor.extraction_context import ExtractionContext
from DyldExtractor.file_context import FileContext


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
	PAGE_SIZE = extractionCtx.PAGE_SIZE

	# first change all the offset fields and record the writes
	writeProcedures = []
	dataHead = 0

	for segname, segment in machoCtx.segments.items():
		# TODO: Don't trust fileoff
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
			# Linkedit Builder already handles the offsets
			LinkeditBuilder(machoCtx).build(dataHead)
			pass
		else:
			# Change the offsets for the segment and section structures
			segment.seg.fileoff += shiftDelta
			for sect in segment.sects.values():
				sect.offset = max(sect.offset + shiftDelta, 0)
				pass
			pass

		# update the data head to the next page aligned offset
		dataHead += segment.seg.filesize
		dataHead += PAGE_SIZE - (dataHead % PAGE_SIZE)
		pass

	return writeProcedures
