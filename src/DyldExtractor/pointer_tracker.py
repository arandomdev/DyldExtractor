from typing import List


class PointerTracker(object):

	def __init__(self) -> None:
		"""A tracker for pointers.
		"""

		super().__init__()
		self.ptrLocs: List[int] = []
		pass

	def addPtr(self, addr: int) -> None:
		"""Add a pointer to the tracker.
		"""

		if addr in self.ptrLocs:
			return
		else:
			self.ptrLocs.append(addr)
			pass
		pass
	pass
