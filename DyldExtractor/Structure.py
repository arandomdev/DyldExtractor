from __future__ import annotations

import copy
import struct

from io import BufferedReader
from typing import Tuple, Union, ClassVar, List


class Structure(object):

	"""A base class for all structures.


	Attributes
	----------
		_fields_ : ClassVar[Tuple[Tuple[str, Union[int, str]]]]
			All Structures need a _fields_ attribute which contains
			all the fields in the structure. Each entry is a Tuple
			with the field's name and an int, if it is a bytes field,
			or an str with a struct format. For example;

				_fields_ = (
					("uint32Field", "<I"),
					("16byteField", 16),
				)
	"""

	_fields_: ClassVar[Tuple[Tuple[Union[int, str]]]] = ()

	@classmethod
	def _getFields(cls) -> List[Tuple[str, Union[int, str]]]:
		"""Gets all the fields in the class.

		Returns
		-------
			List[Tuple[str, Union[int, str]]]
				A list of all the fields in order from the base class
				to the child class.
		"""

		mro = cls.mro()

		fields = []
		for clsDef in reversed(mro):
			if not hasattr(clsDef, "_fields_"):
				continue

			[fields.append(field) for field in clsDef._fields_]
		
		return fields
	
	@classmethod
	def parse(cls, buffer: BufferedReader, offset: int, loadData: bool = True) -> Structure:
		"""Load the structure.

		This method can be overridden to parse fields that cannot
		be encoded in the _fields_ attribute, through super must
		be called.

		Parameters
		----------
			buffer : BufferedReader
				The source of data.
			offset : int
				Byte offset to start at.
			loadData : bool, optional
				Determines if the method "loadData" is called, by
				default True.

		Returns
		-------
			Structure
				An instance of the structure.
		"""

		fields = cls._getFields()

		inst = cls()
		if offset <0:
			print("Structure.parse() offset is negative")
			print("The program will now crash; whatever called this needs to validate its offset.")
			print("-----------")
			# buffer.seek() is going to raise OSError
			# maybe this should be abstracted to a custom internal error?
		buffer.seek(offset)

		for field in fields:
			fieldValue = None
			if isinstance(field[1], str):
				fieldSize = struct.calcsize(field[1])
				fieldValue = struct.unpack(field[1], buffer.read(fieldSize))[0]
			else:
				fieldValue = buffer.read(field[1])
			
			setattr(inst, field[0], fieldValue)
		
		inst._buffer = buffer
		inst._offset = offset

		if loadData:
			inst.loadData()
		
		return inst
	
	@classmethod
	def parseBytes(cls, buffer: bytes, offset: int) -> Structure:
		"""loads the structure with a bytes object.

		Similar to the parse method, this method fills the structure with
		the bytes like object. Though loadData will not be called.

		Parameters
		----------
			buffer : bytes
				Source of data.
			offset : int
				Where to start in the data source.

		Returns
		-------
			Structure
				An instance of the structure.
		"""

		fields = cls._getFields()

		inst = cls()

		bufferHead = offset
		for field in fields:

			fieldValue = None
			if isinstance(field[1], str):
				fieldSize = struct.calcsize(field[1])
				fieldValue = struct.unpack_from(field[1], buffer, bufferHead)[0]

				bufferHead += fieldSize
			else:
				fieldValue = buffer[bufferHead:bufferHead+field[1]]
				bufferHead += field[1]
			
			setattr(inst, field[0], fieldValue)
		
		return inst
	
	def asBytes(self) -> bytes:
		"""Returns the structure in bytes.

		This can be overridden to add any fields not encoded in
		the _fields_ attribute, though super must be called.

		Returns
		-------
			bytes
				The data of the structure.
		"""

		fields = self._getFields()

		data = b""
		for field in fields:
			fieldValue = getattr(self, field[0])

			if isinstance(field[1], str):
				data += struct.pack(field[1], fieldValue)
			else:
				data += fieldValue
		
		return data
	
	def loadData(self) -> None:
		"""Loads extra data.

		This data should be descriptive, and not contained in
		the structure itself
		"""
		...
	
	def __deepcopy__(self, memo):
		newInst = type(self)()
		for var in vars(self):

			if var == "_buffer":
				newInst._buffer = self._buffer
				continue

			value = copy.deepcopy(getattr(self, var), memo)
			setattr(newInst, var, value)
		
		return newInst
	
	@classmethod
	def offsetOf(cls, fieldName: str) -> int:
		"""
		Returns the offset of the field.
		"""
		fields = cls._getFields()

		offset = 0
		for field in fields:
			if field[0] == fieldName:
				return offset
			
			if isinstance(field[1], str):
				offset += struct.calcsize(field[1])
			else:
				offset += field[1]