import argparse
import mmap
from os import path
import pathlib
import sys

import progressbar

from DyldExtractor.dyld.dyld_context import DyldContext

# check dependencies
try:
	assert sys.version_info >= (3, 9, 5)
except AssertionError:
	print("Python 3.9.5 or greater is required", file=sys.stderr)
	exit(1)

try:
	progressbar.streams
except AttributeError:
	print("progressbar is installed but progressbar2 required.", file=sys.stderr)
	exit(1)


class _DyldExtractorArgs(argparse.Namespace):

	dyld_path: pathlib.Path
	extract: str
	output: pathlib.Path

	list_frameworks: bool
	filter: str

	verbosity: int
	pass


def _createArgParser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description="Extract all images from a Dyld Shared Cache.")  # noqa
	parser.add_argument(
		"dyld_path",
		type=pathlib.Path,
		help="A path to the target DYLD cache."
	)
	parser.add_argument(
		"-o", "--output",
		type=pathlib.Path,
		help="Specify the output path for the extracted frameworks. By default it extracts to './binaries/'."  # noqa
	)
	parser.add_argument(
		"-v", "--verbosity",
		choices=[0, 1, 2, 3],
		default=1,
		type=int,
		help="Increase verbosity, Option 1 is the default. | 0 = None | 1 = Critical Error and Warnings | 2 = 1 + Info | 3 = 2 + debug |"  # noqa
	)

	return parser


def _main() -> None:
	argParser = _createArgParser()
	args = argParser.parse_args(namespace=_DyldExtractorArgs())

	print(args)

	# create a list of image paths
	imagesPaths: pathlib.Path = []
	with open(args.dyld_path, "rb") as f:
		dyldFile = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
		dyldCtx = DyldContext(dyldFile)

		for image in dyldCtx.images:
			imagePath = dyldCtx.readString(image.pathFileOffset)[0:-1].decode("utf-8")
			print(imagePath)
			pass
		pass
	pass


if __name__ == "__main__":
	_main()
