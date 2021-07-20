from DyldExtractor.extraction_context import ExtractionContext

from DyldExtractor.macho.macho_context import MachOContext
from DyldExtractor.macho.macho_structs import (
	linkedit_data_command,
	dyld_info_command,
	symtab_command,
	dysymtab_command,
	routines_command_64,
)


_PAGE_SIZE = 0x4000


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


def optimizeOffsets(extractionCtx: ExtractionContext) -> None:
	"""Adjusts file offsets.

		MachO files in the Dyld Shared Cache are split up, which causes
	decached files to have really weird offsets. This fixes that.

	Args:
		machoCtx: A writable MachOContext.

	Returns:
		The processed MachO file.
	"""

	extractionCtx.statusBar.update(unit="Optimize Offsets")

	# The data in a MachO are defined by the segment load commands,
	# This includes the LinkEdit and MachO header
	machoCtx = extractionCtx.machoCtx

	# first change all the offset fields and record the shifts
	shiftProcedures = []  # Essentally a tuple with args to mmap.move
	dataHead = 0

	for segname, segment in machoCtx.segments.items():
		shiftDelta = dataHead - segment.seg.fileoff

		procedure = (
			segment.seg.fileoff + shiftDelta,  # dest
			segment.seg.fileoff,  # src
			segment.seg.filesize  # count
		)
		shiftProcedures.append(procedure)

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

	# Now we need to actually move the segments.
	# 	We are moving the segments now because then we
	# 	don't have to constantly "re-point" various structures.
	for procedure in shiftProcedures:
		extractionCtx.statusBar.update(status="Moving Segments")

		machoCtx.file.move(procedure[0], procedure[1], procedure[2])
		pass

	# re-create the MachOContext so it reflects the new offsets
	extractionCtx.machoCtx = MachOContext(machoCtx.file, 0)
