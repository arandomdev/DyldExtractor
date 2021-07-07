import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))  # noqa

import multiprocessing as mp
import signal
import mmap
import logging
import io
import progressbar
import argparse
import pathlib

from DyldExtractor.macho.macho_context import MachOContext

from DyldExtractor.dyld.dyld_context import DyldContext

from DyldExtractor.extraction_context import ExtractionContext

from DyldExtractor.converter import (
	linkedit_optimizer,
	stub_fixer,
	objc_fixer,
	slide_info,
	macho_offset
)


class _DummyProgressBar(object):
	def update(*args, **kwargs):
		pass


def _imageRunner(dyldPath: str, imageIndex: int) -> None:
	level = logging.DEBUG
	loggingStream = io.StringIO()

	# setup logging
	logger = logging.getLogger(f"Worker: {imageIndex}")
	handler = logging.StreamHandler(loggingStream)
	formatter = logging.Formatter(
		fmt="{asctime}:{msecs:03.0f} [{levelname:^9}] {filename}:{lineno:d} : {message}",  # noqa
		datefmt="%H:%M:%S",
		style="{",
	)

	handler.setFormatter(formatter)
	logger.addHandler(handler)
	logger.setLevel(level)

	# process the image
	with open(dyldPath, "rb") as f:
		dyldFile = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
		dyldCtx = DyldContext(dyldFile)
		imageOffset = dyldCtx.convertAddr(dyldCtx.images[imageIndex].address)

		machoFile = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_COPY)
		machoCtx = MachOContext(machoFile, imageOffset)

		extractionCtx = ExtractionContext(
			dyldCtx,
			machoCtx,
			_DummyProgressBar(),
			logger
		)

		try:
			# TODO: implement a way to select convertors
			# slide_info.processSlideInfo(extractionCtx)
			# linkedit_optimizer.optimizeLinkedit(extractionCtx)
			# stub_fixer.fixStubs(extractionCtx)
			objc_fixer.fixObjC(extractionCtx)
			# macho_offset.optimizeOffsets(extractionCtx)
		except Exception as e:
			logger.exception(e)
		pass

	# cleanup
	handler.close()
	return loggingStream.getvalue()


def _workerInitializer():
	# ignore KeyboardInterrupt in workers
	signal.signal(signal.SIGINT, signal.SIG_IGN)
	pass


if "__main__" == __name__:
	# Get arguments
	parser = argparse.ArgumentParser()
	parser.add_argument(
		"dyld_path",
		type=pathlib.Path,
		help="A path to the target DYLD cache."
	)
	args = parser.parse_args()

	# create a list of images
	images: list[str] = []
	with open(args.dyld_path, "rb") as f:
		dyldFile = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
		dyldCtx = DyldContext(dyldFile)

		for index, image in enumerate(dyldCtx.images):
			imagePath = dyldCtx.readString(image.pathFileOffset)[0:-1]
			imagePath = imagePath.decode("utf-8")
			imageName = imagePath.split("/")[-1]

			images.append(imageName)
		pass

	summary = ""
	with mp.Pool(initializer=_workerInitializer) as pool:
		# create jobs for each image
		jobs: list[tuple[str, mp.pool.AsyncResult]] = []
		for index, imageName in enumerate(images):
			jobs.append(
				(imageName, pool.apply_async(_imageRunner, (args.dyld_path, index)))
			)
			pass

		total = len(jobs)
		jobsComplete = 0

		# setup progress bar
		statusBar = progressbar.ProgressBar(
			max_value=total,
			redirect_stdout=True
		)

		# wait for all the jobs to complete
		while True:
			if len(jobs) == 0:
				break

			for i in reversed(range(len(jobs))):
				imageName, job = jobs[i]
				if job.ready():
					jobs.pop(i)

					# update the status
					jobsComplete += 1
					statusBar.update(jobsComplete)
					print(f"processed: {imageName}")

					# print the result if any
					result = job.get()
					if len(result):
						result = f"----- {imageName} -----\n{result}--------------------\n"
						summary += result
						print(result)

			pass

		# close the pool and cleanup
		pool.close()
		pool.join()
		statusBar.update(jobsComplete)
		pass

	print("\n\n----- Summary -----")
	print(summary)
	print("-------------------\n\n")
	pass
