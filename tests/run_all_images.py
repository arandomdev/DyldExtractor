import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))  # noqa

import progressbar
import mmap
import logging
import argparse
import pathlib
from io import BufferedReader

from DyldExtractor.extraction_context import ExtractionContext

from DyldExtractor.dyld.dyld_context import DyldContext

from DyldExtractor.macho.macho_context import MachOContext
from DyldExtractor.macho.macho_constants import *

from DyldExtractor.converter import (
	macho_offset,
	slide_info,
	linkedit_optimizer,
	stub_fixer,
	objc_fixer
)


def getArguments():
	"""Get program arguments.

	"""

	parser = argparse.ArgumentParser()
	parser.add_argument(
		"dyld_path",
		type=pathlib.Path,
		help="A path to the target DYLD cache."
	)

	return parser.parse_args()


def runForAllImages(
	dyldFile: BufferedReader,
	dyldCtx: DyldContext,
	statusBar: progressbar.ProgressBar,
	logger: logging.Logger,
	startIndex: int = 0,
	stopIndex: int = -1
) -> None:
	total = dyldCtx.header.imagesCount

	for index, imageData in enumerate(dyldCtx.images[startIndex:], startIndex):
		if index == stopIndex:
			break

		imageOffset = dyldCtx.convertAddr(imageData.address)
		imagePath = dyldCtx.readString(imageData.pathFileOffset)[0:-1]
		imagePath = imagePath.decode("utf-8")
		imageName = imagePath.split("/")[-1]

		# Make a writable copy of the dyld file
		machoFile = mmap.mmap(dyldFile.fileno(), 0, access=mmap.ACCESS_COPY)
		machoCtx = MachOContext(machoFile, imageOffset)

		extractionCtx = ExtractionContext(dyldCtx, machoCtx, statusBar, logger)

		# Test space start

		slide_info.processSlideInfo(extractionCtx)
		linkedit_optimizer.optimizeLinkedit(extractionCtx)
		stub_fixer.fixStubs(extractionCtx)
		objc_fixer.fixObjC(extractionCtx)
		macho_offset.optimizeOffsets(extractionCtx)

		# Test space end

		logger.info(f"processed: ({index + 1}/{total}): {imageName}")
		pass

	statusBar.update(unit="Extractor", status="Done")
	pass


class LoggingBreakPoint(logging.Handler):

	IGNORE_FILTER = (
		"processed",
		"Unable to get __stub_helper section",
		"Unable to find dependency",
		"Unable to get stubs section",
		"ObjC was not optimized by Dyld"
	)

	def emit(self, record: logging.LogRecord) -> None:
		for term in self.IGNORE_FILTER:
			if term in record.message:
				return

		breakpoint()


def main():
	level = logging.DEBUG

	progressbar.streams.wrap_stderr()  # needed for logging compatability
	logging.basicConfig(
		format="{asctime}:{msecs:03.0f} [{levelname:^9}] {filename}:{lineno:d} : {message}",  # noqa
		datefmt="%H:%M:%S",
		style="{",
		level=level
	)

	logger = logging.getLogger()
	logger.addHandler(LoggingBreakPoint())

	statusBar = progressbar.ProgressBar(
		prefix="{variables.unit} >> {variables.status} :: [",
		variables={"unit": "--", "status": "--"},
		widgets=[progressbar.widgets.AnimatedMarker(), "]"],
		redirect_stdout=True
	)

	args = getArguments()

	with open(args.dyld_path, "rb") as f:
		dyldFile = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
		dyldCtx = DyldContext(dyldFile)

		# runForAllImages(f, dyldCtx, statusBar, logger, stopIndex=1030)
		# runForAllImages(f, dyldCtx, statusBar, logger, startIndex=1020)
		runForAllImages(f, dyldCtx, statusBar, logger)
	pass


if "__main__" == __name__:
	main()
