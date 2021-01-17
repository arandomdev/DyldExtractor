from DyldExtractor.Dyld.DyldFile import DyldFile
import typing
import argparse
import pathlib

from DyldExtractor import Dyld

def enumerateImages(dyld: Dyld.DyldFile) -> typing.List[typing.Tuple[int, str, str]]:
	"""Enumerate the images in the Dyld Cache.

	Returned as a list of tuples containing the image index, name, and path.
	"""

	images = []

	for i in range(0, len(dyld.images)):
		image = dyld.images[i]
		
		imagePath = dyld.readString(image.pathFileOffset)
		imagePath = imagePath.decode("utf-8")

		imageName = imagePath.split("/")[-1]

		images.append((i, imageName, imagePath))
	
	return images


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("dyld_path", type=pathlib.Path, help="A path to the target DYLD cache.")
	parser.add_argument("-f", "--framework", help="The name of the framework to extract.")
	
	parser.add_argument("-l", "--list-frameworks", action="store_true", help="List all frameworks in the cache.")
	parser.add_argument("--filter", help="Filter out frameworks when listing them.")

	args = parser.parse_args()

	with open(args.dyld_path, mode="rb") as dyldFileHandle:
		dyldFile = Dyld.DyldFile(dyldFileHandle)
		
		if args.list_frameworks:
			images = enumerateImages(dyldFile)
			
	pass