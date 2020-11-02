"""
Useful links
	https://opensource.apple.com/source/xnu/xnu-6153.81.5/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
	https://opensource.apple.com/source/objc4/objc4-781/runtime/objc-runtime-new.h.auto.html
	
	https://opensource.apple.com/source/dyld/dyld-733.6/launch-cache/dyld_cache_format.h.auto.html
	https://opensource.apple.com/source/dyld/dyld-733.6/launch-cache/dsc_extractor.cpp.auto.html

	https://github.com/deepinstinct/dsc_fix/blob/master/dsc_fix.py
	https://github.com/kennytm/Miscellaneous/blob/master/dyld_decache.cpp
	https://github.com/phoenix3200/decache/blob/master/decache.mm

	https://worthdoingbadly.com/dscextract/
	https://github.com/zhuowei/dsc_extractor_badly/blob/master/launch-cache/dsc_extractor.cpp

	https://static.docs.arm.com/ddi0596/a/DDI_0596_ARM_a64_instruction_set_architecture.pdf
"""

import copy
import os
import struct

from DyldExtractor import Dyld
from DyldExtractor import MachO

from DyldExtractor.Converter.OffsetConverter import OffsetConverter
from DyldExtractor.Converter.LinkeditConverter import LinkeditConverter, RebaseConverter
from DyldExtractor.Converter.StubConverter import StubConverter
from DyldExtractor.Converter.ObjCConvertor import ObjCConverter
from DyldExtractor.Converter.SelectorConvertor import SelectorConverter


# Change this to point to your cache
DYLD_PATH = os.path.join(os.getcwd(), "binaries\\dyld_shared_cache_arm64")


def runAllImages():
	"""
	Test a module with all images in the cache	
	"""

	with open(DYLD_PATH, "rb") as dyldFile:
		dyld = Dyld.DyldFile(dyldFile)

		totalImages = len(dyld.images)
		for i in range(1, totalImages):
			image = dyld.images[i]

			imagePath = dyld.readString(image.pathFileOffset)
			imageName = imagePath.split(b"/")[-1].decode("utf-8")

			print("{}/{}: {}".format(i, totalImages, imageName))

			imageOff = dyld.convertAddr(image.address)
			macho = MachO.MachoFile.parse(dyldFile, imageOff)
			
			# LinkeditConverter(macho, dyld).convert()
			# RebaseConverter(macho, dyld).convert()
			SelectorConverter(macho, dyld).convert()
			# StubConverter(macho, dyld).convert()
			# ObjCConverter(macho, dyld).convert()
			# OffsetConverter(macho).convert()
			# MachO.Writer(macho).writeToPath(TEMP_PATH)


def runOnce(imageIndex: int, path: str) -> None:
	"""
	Decache an image at the imageIndex, and save it to the path.
	"""

	with open(DYLD_PATH, "rb") as dyldFile:
		dyld = Dyld.DyldFile(dyldFile)

		image = dyld.images[imageIndex]

		imageOff = dyld.convertAddr(image.address)
		macho = MachO.MachoFile.parse(dyldFile, imageOff)
		
		# comment or uncomment lines below to enable or disable modules. Though some do rely on each other.
		# rebuild the linkedit segment, which includes symbols
		print("LinkeditConverter")
		LinkeditConverter(macho, dyld).convert()

		# remove extra data in pointers and generate rebase data
		print("RebaseConverter")
		RebaseConverter(macho, dyld).convert()

		# fix references to selectors
		print("SelectorConverter")
		SelectorConverter(macho, dyld).convert()

		# fix stubs and references to stubs
		print("StubConverter")
		StubConverter(macho, dyld).convert()

		# fix and decache ObjC info
		print("ObjCConverter")
		ObjCConverter(macho, dyld).convert()

		# changes file offsets so that the final MachO file is not GBs big
		print("OffsetConverter")
		OffsetConverter(macho).convert()

		# save the converted image to a file
		print("Writer")
		MachO.Writer(macho).writeToPath(path)


def listImages(filterTerm: bytes = b""):
	"""
	Prints all the images in the cache with an optional filter term.
	"""	

	with open(DYLD_PATH, "rb") as dyldFile:
		dyld = Dyld.DyldFile(dyldFile)

		for image in dyld.images:
			dyldFile.seek(image.pathFileOffset)
			path = b""
			while True:
				data = dyldFile.read(1)
				path += data
				if data == b"\x00":
					break

			if filterTerm.lower() in path.lower():
				print(str(path) + ": " + str(dyld.images.index(image)))


if __name__ == "__main__":
	# Search for an image
	listImages(b"voice")

	# decache an image
	imagePath = os.path.join(os.getcwd(), "binaries\\VoiceShortcuts")
	runOnce(703, imagePath)
	pass