from DyldExtractor.macho.macho_context import MachOContext


class LinkeditBuilder(object):

	def __init__(self, machoCtx: MachOContext) -> None:
		"""Builds the linkedit segment.

		Args:
			machoCtx: A writable MachOContext to manage.
		"""

		super().__init__()
		self._machoCtx = machoCtx

		self._loadCommands = []
		pass

	def _processLoadCommands(self) -> None:

		pass
	pass
