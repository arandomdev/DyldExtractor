#!/usr/bin/env python3

import copy
import os, sys
import struct

from DyldExtractor import Dyld
from DyldExtractor import MachO

from DyldExtractor.Converter.OffsetConverter import OffsetConverter
from DyldExtractor.Converter.LinkeditConverter import LinkeditConverter, RebaseConverter
from DyldExtractor.Converter.StubConverter import StubConverter
from DyldExtractor.Converter.ObjCConvertor import ObjCConverter
from DyldExtractor.Converter.SelectorConvertor import SelectorConverter

# MacOS Location
DYLD_PATH = "/private/var/db/dyld/dyld_shared_cache_x86_64h"


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


def listImages(filterTerm: str):
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

			if filterTerm.lower() in path.lower().decode("utf-8"):
				print(path.decode("utf-8") + ": " + str(dyld.images.index(image)))


def extract(framework: str, out: str):
	with open(DYLD_PATH, "rb") as dyldFile:
		dyld = Dyld.DyldFile(dyldFile)

		for image in dyld.images:
			dyldFile.seek(image.pathFileOffset)
			path = b""
			while True:
				data = dyldFile.read(1)
				if data != b"\x00":
					path += data
				else:
					break
			#
			if framework.lower() == str(os.path.basename(path.decode("utf-8"))).lower():
				runOnce(dyld.images.index(image), out)
			elif framework in path.decode("utf-8"):
				pass
			else:
				pass
				# print("hm")


if __name__ == "__main__":
	# we should probably use argparse for this
	# counterpoint: this is more readable and dependencies stink
	try:
		for i, arg in enumerate(sys.argv[1:]):
			if "-c" == arg:
				DYLD_PATH = sys.argv[i+2]
			elif "-e" == arg:
				FW = sys.argv[i+2]
			elif "-o" == arg:
				OUT = sys.argv[i+2]
		# We catch the error if these aren't defined
		# Lazy, maybe, but why not
		extract(FW, OUT)
	except (IndexError, NameError):
		print("Usage - ./extractor.py [-c <dyld_shared_cache path>] -e <Framework Name> -o <Output File>")
		exit(1)
	except FileNotFoundError:
		# this might cause problems
		print(f'Couldn\'t find {DYLD_PATH}')
		exit(1)

