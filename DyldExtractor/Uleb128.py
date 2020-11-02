import typing

def readUleb128(buffer: bytes, offset: int) -> typing.Tuple[int, int]:
	"""Reads an Uleb128 from the buffer.

	Reads Uleb128 encoded data from the buffer at the
	given offset.

	Parameters
	----------
		buffer : bytes
			Source of data.
		offset : int
			Where to start in the buffer.

	Returns
	-------
		Tuple[int, int]
			A tuple with the uleb value and how many bytes
			it uses.

	Raises
	------
		Exception
			Raises "Uleb extends beyond buffer" if the uleb
			consumes pass the buffer.
	"""

	value = 0
	shift = 0
	readHead = offset
	
	while True:
		if offset >= len(buffer):
			raise Exception("Uleb extends beyond buffer")

		byte = buffer[readHead]
		
		value |= (byte & 0x7f) << shift
		
		readHead += 1
		shift += 7

		if (byte & 0x80) == 0:
			break
	
	return (value, readHead - offset)

def encodeUleb128(value: int) -> bytes:
	"""Encodes a value into Uleb128 format.

	Parameters
	----------
		value : int
			The value to encode.

	Returns
	-------
		bytes
			The Uleb128 interpretation.
	"""

	if value == 0:
		return b"\x00"

	data = bytearray()

	while value != 0:
		currentSlice = value & 0x7f
		value >>= 7
		
		if value != 0:
			currentSlice |= 0x80
		
		data.append(currentSlice)
	
	return bytes(data)