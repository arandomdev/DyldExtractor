from typing import Set


class PointerTracker(object):

	def __init__(self) -> None:
		"""A tracker for pointers.
		"""

		super().__init__()
		self.ptrLocs: Set[int] = set()
		pass

	def addPtr(self, addr: int) -> None:
		"""Add a pointer to the tracker.
		"""

		self.ptrLocs.add(addr)
		pass
	pass
