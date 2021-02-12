#!/usr/bin/env python3

from DyldExtractor.Dyld.DyldFile import DyldFile
import typing
import argparse
import pathlib
import logging
import os

from DyldExtractor import Dyld
from DyldExtractor import MachO
from DyldExtractor import Converter

def enumerateImages(dyld: Dyld.DyldFile) -> typing.List[typing.Tuple[int, str, str]]:
	"""Enumerate the images in the Dyld Cache.

	Returned as a list of tuples containing the image index, name, and path.

	Args:
		dyld: the DyldFile to enumerate from.
	
	returns:
		a list of tuples that contain the image index, name, and the path
		of the image
	"""

	images = []

	for i in range(0, len(dyld.images)):
		image = dyld.images[i]
		
		imagePath = dyld.readString(image.pathFileOffset)
		imagePath = imagePath[0:-1] # remove the null terminator
		imagePath = imagePath.decode("utf-8")

		imageName = imagePath.split("/")[-1]

		images.append((i, imageName, imagePath))
	
	return images


def extractImage(dyld: Dyld.DyldFile, image: Dyld.dyld_cache_image_info, outputPath: str) -> None:
	"""Extract and image
	
	Args:
		dyld: The DyldFile to extract from.
		image: The target image to extract.
		outputPath: The path to extract to.
	"""

	imageOff = dyld.convertAddr(image.address)

	machoFile = MachO.MachoFile.parse(dyld.file, imageOff)

	# rebuild the linkedit segment, which includes symbols
	logging.info("Starting LinkeditConverter")
	Converter.LinkeditConverter(machoFile, dyld).convert()

	# remove extra data in pointers and generate rebase data
	logging.info("Starting RebaseConverter")
	# Converter.RebaseConverter(machoFile, dyld).convert()

	# fix references to selectors
	logging.info("Starting SelectorConverter")
	# Converter.SelectorConverter(machoFile, dyld).convert()

	# fix stubs and references to stubs
	logging.info("Starting StubConverter")
	# Converter.StubConverter(machoFile, dyld).convert()

	# fix and decache ObjC info
	logging.info("Starting ObjCConverter")
	# Converter.ObjCConverter(machoFile, dyld).convert()

	# changes file offsets so that the final MachO file is not GBs big
	logging.info("Starting OffsetConverter")	
	Converter.OffsetConverter(machoFile).convert()

	# save the converted image to a file
	logging.info("Starting Writer")
	MachO.Writer(machoFile).writeToPath(outputPath)
	pass


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("dyld_path", type=pathlib.Path, help="A path to the target DYLD cache.")
	parser.add_argument("-f", "--framework", help="The name of the framework to extract.")
	parser.add_argument("-o", "--output", help="Specify the output path for the extracted framework. By default it extracts to the binaries folder.")
	
	parser.add_argument("-l", "--list-frameworks", action="store_true", help="List all frameworks in the cache.")
	parser.add_argument("--filter", help="Filter out frameworks when listing them.")

	parser.add_argument("-v", "--verbosity", type=int, choices=[0, 1, 2, 3], default=1, help="Increase verbosity, Option 1 is the default. | 0 = None | 1 = Critical Error and Warnings | 2 = 1 + Info | 3 = 2 + debug |")

	args = parser.parse_args()

	# configure Logging
	level = logging.WARNING # default options

	if args.verbosity == 0:
		# Set the log level so high that it doesn't do anything
		level = 100
	elif args.verbosity == 2:
		level = logging.INFO
	elif args.verbosity == 3:
		level = logging.DEBUG
	
	logging.basicConfig(
		format="%(asctime)s:%(msecs)03d %(filename)s [%(levelname)-8s] : %(message)s",
		datefmt="%H:%M:%S",
		level=level
	)

	with open(args.dyld_path, mode="rb") as dyldFileHandle:
		dyldFile = Dyld.DyldFile(dyldFileHandle)
		images = enumerateImages(dyldFile)

		# List Images option
		if args.list_frameworks:	
			if args.filter:
				filterTerm = args.filter.lower()
				images = [x for x in images if filterTerm in x[2].lower()]

			print("Listing images")
			print(f"Index| {'Name':40} | Path")
			for image in images:
				print(f"{image[0]:4} | {image[1]:40} | {image[2]}")
		
		# Extract image Option
		elif args.framework:	
			targetFramework = args.framework.strip()
			targetImageData = None
			for image in images:
				if targetFramework == image[1]:
					targetImageData = image
					break

			if not targetImageData:
				print(f"Unable to find {targetFramework} in cache")
				exit()

			print("Extracting " + targetImageData[1])
			if args.output:
				extractImage(dyldFile, dyldFile.images[targetImageData[0]], args.output)
			else:
				# create the binaries folder
				os.makedirs("binaries", exist_ok=True)
				extractImage(dyldFile, dyldFile.images[targetImageData[0]], "binaries\\"+targetImageData[1])
		else:
			print("Specify a framework to extract, see -h")
	pass