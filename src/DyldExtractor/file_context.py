import struct
from mmap import mmap
from typing import Any


class FileContext:

	fileOffset: int
	file: mmap

	def __init__(self, file: mmap, offset: int = 0) -> None:
		self.fileOffset = offset
		self.file = file
		pass

	def readString(self, offset: int) -> bytes:
		"""Read a null terminated c-string.

		Args:
			offset: the file offset to the start of the string.

		Returns:
			The string in bytes, including the null terminater.
		"""

		nullIndex = self.file.find(b"\x00", offset)
		if nullIndex == -1:
			return None

		return self.file[offset:nullIndex + 1]

	def readFormat(self, offset: int, format: str) -> Any:
		"""Read a formatted value at the offset.

		Args:
			offset: the file offset to read from.
			format: the struct format to pass to struct.unpack.

		Return:
			The formated value.
		"""

		size = struct.calcsize(format)
		return struct.unpack(format, self.file[offset:offset + size])

	def getBytes(self, offset: int, length: int) -> bytes:
		"""Retrieve data from the datasource.

		Args:
			offset: The location to start at.
			length: How many bytes to read.

		Return:
			The data requested.
		"""

		return self.file[offset:offset + length]

	def writeBytes(self, offset: int, data: bytes) -> None:
		"""Writes the data at the offset.

		Args:
			offset: the file offset.
			data: the data to write
		"""

		self.file.seek(offset)
		self.file.write(data)
		pass
