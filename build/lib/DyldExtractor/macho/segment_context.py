from mmap import mmap
from typing import List, Dict


from DyldExtractor.macho.macho_structs import (
	segment_command_64,
	section_64
)


class SegmentContext(object):

	seg: segment_command_64

	sects: Dict[bytes, section_64]
	sectsI: List[section_64]

	def __init__(self, file: mmap, segment: segment_command_64) -> None:
		"""Represents a segment.

		This holds information regarding a segment and its sections.

		Args:
			file: The data source used for the segment.
			segment: The segment structure.
		"""

		super().__init__()

		self.seg = segment

		self.sects = {}
		self.sectsI = []

		sectsStart = segment._fileOff_ + len(segment)
		for i in range(segment.nsects):
			sectOff = sectsStart + (i * section_64.SIZE)
			sect = section_64(file, sectOff)

			self.sects[sect.sectname] = sect
			self.sectsI.append(sect)
