import struct
import mmap

from typing import (
	Any,
	Tuple,
	BinaryIO
)


class FileContext:

	def __init__(
		self,
		fileObject: BinaryIO,
		copyMode: bool = False
	) -> None:
		self.fileObject = fileObject
		self.file = mmap.mmap(
			fileObject.fileno(),
			0,
			access=mmap.ACCESS_COPY if copyMode else mmap.ACCESS_READ
		)
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

	def readFormat(self, format: str, offset: int) -> Tuple[Any, ...]:
		"""Read a formatted value at the offset.

		Args:
			offset: the file offset to read from.
			format: the struct format to pass to struct.unpack.

		Return:
			The formated value.
		"""

		return struct.unpack_from(format, self.file, offset)

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

	def makeCopy(self, copyMode: bool = False) -> "FileContext":
		return type(self)(self.fileObject, copyMode=copyMode)

	pass
