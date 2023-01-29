import progressbar
import logging

from DyldExtractor.cache_context import CacheContext
from DyldExtractor.macho.macho_context import MachOContext


class ExtractionContext(object):
	"""Holds state information for extraction
	"""

	dyldCtx: CacheContext
	machoCtx: MachOContext

	# The update method of the the progress bar has
	# "unit" and "status" keyword arguments.
	statusBar: progressbar.ProgressBar
	logger: logging.Logger

	"""
		If this variable is true, the following is true,
		* There are redacted indirect symbol entries
		* Space was allocated for the redacted symbol entries
			* This space is placed at the end of the symbol table
		* The string table to at the end of the LINKEDIT segment.
	"""
	hasRedactedIndirect: bool = False

	# The name of the extra data segment
	# And an out of file location to store it.
	EXTRA_SEGMENT_NAME = b"__EXTRA_OBJC"
	extraSegmentData: bytes

	def __init__(
		self,
		dyldCtx: CacheContext,
		machoCtx: MachOContext,
		statusBar: progressbar.ProgressBar,
		logger: logging.Logger
	) -> None:
		super().__init__()

		self.dyldCtx = dyldCtx
		self.machoCtx = machoCtx
		self.statusBar = statusBar
		self.logger = logger
		pass
	pass
