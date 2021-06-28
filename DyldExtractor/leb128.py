

def decodeUleb128(buffer: bytes, readHead: int) -> tuple[int, int]:
	"""Read a Uleb128 value.

	Args:
		buffer: The data source.
		readHead: The initial offset to read from.

	Returns:
		A tuple containing the result and the new read head.
	"""

	value = 0
	shift = 0

	while True:
		if readHead >= len(buffer):
			raise Exception("Uleb extends beyond buffer")

		byte = buffer[readHead]

		value |= (byte & 0x7f) << shift

		readHead += 1
		shift += 7

		if (byte & 0x80) == 0:
			break

	return (value, readHead)


def encodeUleb128(value: int) -> bytes:
	"""Encodes the given value in Uleb128 format.

	Args:
		value: The value to encode.

	Returns:
		The encoded number
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


def decodeSleb128(buffer: bytes, readHead: int) -> tuple[int, int]:
	"""Read a 64bit Sleb128 value.

	Args:
		buffer: The data source.
		readHead: The initial offset to read from.

	Returns:
		A tuple containing the result and the new read head.
	"""

	RESULT_SIZE = 64

	result = 0
	shift = 0

	while True:
		if readHead >= len(buffer):
			raise Exception("Uleb extends beyond buffer")

		byte = buffer[readHead]
		result |= (byte & 0x7f) << shift

		readHead += 1
		shift += 7

		if (byte & 0x80) == 0:
			if shift < RESULT_SIZE and byte & 0x40:
				result |= (~0 << shift)

			break

	return (result, readHead)
