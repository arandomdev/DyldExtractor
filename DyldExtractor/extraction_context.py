import progressbar
import logging

from DyldExtractor.dyld.dyld_context import DyldContext
from DyldExtractor.macho.macho_context import MachOContext


class ExtractionContext(object):
	"""Holds state information for extraction
	"""

	dyldCtx: DyldContext
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

	def __init__(
		self,
		dyldCtx: DyldContext,
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
