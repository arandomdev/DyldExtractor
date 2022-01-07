from typing import Dict

from DyldExtractor.builder.linkedit_builder import LinkeditBuilder
from DyldExtractor.extraction_context import ExtractionContext
from DyldExtractor.file_context import FileContext
from DyldExtractor import leb128

from DyldExtractor.macho.macho_constants import *
from DyldExtractor.macho.macho_structs import LoadCommands


def _organizeSegments(extractionCtx: ExtractionContext) -> Dict[int, int]:
	"""Organize the segments by vmaddr.

	Returns:
		A map from the old segment indices to the new ones.
	"""

	machoCtx = extractionCtx.machoCtx

	# validate that the segments are all next to each other
	startCount = False
	nSegs = 0
	for lc in machoCtx.loadCommands:
		if lc.cmd == LoadCommands.LC_SEGMENT_64:
			nSegs += 1
			startCount = True
			pass
		else:
			if startCount:
				break
			pass
		pass

	if nSegs != len(machoCtx.segmentsI):
		extractionCtx.logger.error("Segments are not next to each other, unable to organize segments")  # noqa
		return

	# Organize and create map
	segments = sorted(machoCtx.segmentsI, key=lambda seg: seg.seg.vmaddr)
	mapping = {}
	for segI, seg in enumerate(machoCtx.segmentsI):
		mapping[segI] = segments.index(seg)
		pass

	# Write
	segmentData = bytearray()
	for seg in segments:
		segmentData.extend(seg.seg)
		segmentData.extend(b"".join(seg.sectsI))
		pass

	segStart = machoCtx.segmentsI[0].seg._fileOff_
	machoCtx.writeBytes(segStart, segmentData)
	machoCtx.reloadLoadCommands()

	return mapping


def _opcodeProcessor(
	fileCtx: FileContext,
	bindOff: int,
	bindSize: int,
	segMap: Dict[int, int],
	segFills: Dict[int, int]
) -> bytes:
	file = fileCtx.file
	newBindingInfo = bytearray()

	dataEnd = bindOff + bindSize
	while bindOff < dataEnd:
		bindOpcodeImm = file[bindOff]
		opcode = bindOpcodeImm & BIND_OPCODE_MASK
		imm = bindOpcodeImm & BIND_IMMEDIATE_MASK

		newBindingInfo.append(bindOpcodeImm)
		bindOff += 1

		if opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
			# Update the segment index
			newSegI = segMap[imm]
			newBindingInfo[-1] = opcode | newSegI

			oldOff, newReadHead = leb128.decodeUleb128(file, bindOff)
			if imm not in segFills:
				newBindingInfo.extend(fileCtx.getBytes(bindOff, newReadHead - bindOff))
			else:
				# Add the fill to the old offset
				newOffsetData = oldOff + segFills[newSegI]
				newBindingInfo.extend(leb128.encodeUleb128(newOffsetData))
				pass

			bindOff = newReadHead
			pass

		elif opcode in (
			BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB,
			BIND_OPCODE_ADD_ADDR_ULEB,
			BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB,
			BIND_OPCODE_SET_ADDEND_SLEB
		):
			length = leb128.decodeLength(file, bindOff)
			newBindingInfo.extend(fileCtx.getBytes(bindOff, length))
			bindOff += length
			pass
		elif opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
			length = leb128.decodeLength(file, bindOff)
			length += leb128.decodeLength(file, bindOff + length)
			newBindingInfo.extend(fileCtx.getBytes(bindOff, length))
			bindOff += length
			pass
		elif opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
			symbol = fileCtx.readString(bindOff)
			newBindingInfo.extend(symbol)
			bindOff += len(symbol)
			pass
		elif opcode in (
			BIND_OPCODE_SET_DYLIB_ORDINAL_IMM,
			BIND_OPCODE_SET_DYLIB_SPECIAL_IMM,
			BIND_OPCODE_SET_TYPE_IMM,
			BIND_OPCODE_DO_BIND,
			BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED,
			BIND_OPCODE_DONE
		):
			pass
		else:
			raise KeyError(f"Unknown bind opcode: {opcode}")
		pass

	return newBindingInfo


def _fixBindinfo(
	extractionCtx: ExtractionContext,
	segMap: Dict[int, int],
	segFills: Dict[int, int]
):
	"""Update binding info with new segment offsets.
	"""

	machoCtx = extractionCtx.machoCtx
	linkeditSeg = machoCtx.segments[b"__LINKEDIT"].seg
	linkeditCtx = machoCtx.ctxForAddr(linkeditSeg.vmaddr)

	builder = LinkeditBuilder(machoCtx)
	dyldInfoData = builder.dyldInfoData
	if not dyldInfoData:
		return

	dyldInfoCmd = dyldInfoData.command

	if dyldInfoCmd.bind_size:
		newData = _opcodeProcessor(
			linkeditCtx,
			dyldInfoCmd.bind_off,
			dyldInfoCmd.bind_size,
			segMap,
			segFills
		)
		dyldInfoData.bindData = newData
		pass
	if dyldInfoCmd.weak_bind_size:
		newData = _opcodeProcessor(
			linkeditCtx,
			dyldInfoCmd.weak_bind_off,
			dyldInfoCmd.weak_bind_size,
			segMap,
			segFills
		)
		dyldInfoData.weakBindData = newData
		pass
	if dyldInfoCmd.lazy_bind_size:
		newData = _opcodeProcessor(
			linkeditCtx,
			dyldInfoCmd.lazy_bind_off,
			dyldInfoCmd.lazy_bind_size,
			segMap,
			segFills
		)
		dyldInfoData.lazyBindData = newData
		pass

	builder.build(extractionCtx.dyldCtx.convertAddr(linkeditSeg.vmaddr)[0])
	pass


def _pageAlignSegments(extractionCtx: ExtractionContext) -> Dict[int, int]:
	"""Attempt to page align the beginning of segments.

	Returns:
		A map of segment indices and their fill amount.
	"""

	machoCtx = extractionCtx.machoCtx
	dyldCtx = extractionCtx.dyldCtx

	segFills = {}

	for segI, seg in enumerate(machoCtx.segmentsI):
		seg = seg.seg
		fill = seg.vmaddr % extractionCtx.PAGE_SIZE
		if fill == 0:
			continue

		if seg.segname == b"__LINKEDIT":
			extractionCtx.logger.error("Unable to page align LINKEDIT segment.")
			continue

		# verify that it will not collide with the segment before it
		if segI != 0:
			lastSeg = machoCtx.segmentsI[segI - 1].seg
			lastSegEnd = lastSeg.vmaddr + lastSeg.vmsize
			if seg.vmaddr - fill < lastSegEnd:
				extractionCtx.logger.error("Unable to page align segment due to collision.")  # noqa
				continue
			pass

		segFills[segI] = fill

		# fill with zero and update load command
		segOff = dyldCtx.convertAddr(seg.vmaddr)[0]
		segCtx = machoCtx.ctxForAddr(seg.vmaddr)

		segCtx.writeBytes(segOff - fill, b"\x00" * fill)
		seg.vmaddr -= fill
		seg.vmsize += fill
		seg.fileoff -= fill
		seg.filesize += fill
		pass

	return segFills


def fixSegments(extractionCtx: ExtractionContext):
	"""Fix segments.

	While this convertor is not necessary for RE, it
	fixes some issues for running images.
	"""

	segMap = _organizeSegments(extractionCtx)
	segFills = _pageAlignSegments(extractionCtx)
	_fixBindinfo(extractionCtx, segMap, segFills)
	pass
