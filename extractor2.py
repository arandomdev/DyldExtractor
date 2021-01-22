from DyldExtractor.Dyld.DyldStructs import dyld_cache_image_info
import typing
import argparse
import pathlib
import logging

from DyldExtractor import Dyld
from DyldExtractor import MachO
from DyldExtractor import Converter

def enumerateImages(dyld: Dyld.DyldFile) -> typing.List[typing.Tuple[int, str, str]]:
	"""Enumerate the images in the Dyld Cache.

	Returned as a list of tuples containing the image index, name, and path.
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
	imageOff = dyld.convertAddr(image.address)

	machoFile = MachO.MachoFile.parse(dyld, imageOff)

	# rebuild the linkedit segment, which includes symbols
	logging.info("Start LinkeditConverter")
	Converter.LinkeditConverter(machoFile, dyld).convert()

	# remove extra data in pointers and generate rebase data
	logging.info("Starting RebaseConverter")
	Converter.RebaseConverter(machoFile, dyld).convert()

	# fix references to selectors
	logging.info("Starting SelectorConverter")
	Converter.SelectorConverter(machoFile, dyld).convert()

	# fix stubs and references to stubs
	logging.info("Starting StubConverter")
	Converter.StubConverter(machoFile, dyld).convert()

	# fix and decache ObjC info
	logging.info("Starting ObjCConverter")
	Converter.ObjCConverter(machoFile, dyld).convert()

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
	
	parser.add_argument("-l", "--list-frameworks", action="store_true", help="List all frameworks in the cache.")
	parser.add_argument("--filter", help="Filter out frameworks when listing them.")

	args = parser.parse_args()

	with open(args.dyld_path, mode="rb") as dyldFileHandle:
		dyldFile = Dyld.DyldFile(dyldFileHandle)
		
		images = enumerateImages(dyldFile)

		if args.list_frameworks:	
			if args.filter:
				filterTerm = args.filter.lower()
				images = [x for x in images if filterTerm in x[2].lower()]

			print("Listing images")
			print(f"Index| Name                                    | Path")
			for image in images:
				print(f"{image[0]:4} | {image[1]:40} | {image[2]}")
		
		if args.framework:	
			targetImage = None
			for image in images:
				if args.framework in image[1]:
					targetImage = image
					break

			print(targetImage)
			
			if not targetImage:
				print(f"Unable to find {args.framework} in cache")
		else:
			print("Specify a framework to extract, see -h")
	pass