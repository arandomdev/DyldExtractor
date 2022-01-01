import multiprocessing as mp
import signal
import logging
import io
import progressbar
import argparse
import pathlib

from typing import (
	Tuple,
	List,
	BinaryIO
)

from DyldExtractor.file_context import FileContext
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


class _DyldExtractorArgs(argparse.Namespace):

	dyld_path: pathlib.Path
	jobs: int
	pass


class _DummyProgressBar(object):
	def update(*args, **kwargs):
		pass


def _openSubCaches(
	mainCachePath: str,
	numSubCaches: int
) -> Tuple[List[FileContext], List[BinaryIO]]:
	"""Create FileContext objects for each sub cache.

	Assumes that each sub cache has the same base name as the
	main cache, and that the suffixes are preserved.

	Also opens the symbols cache, and adds it to the end of
	the list.

	Returns:
		A list of subcaches, and their file objects, which must be closed!
	"""
	subCaches = []
	subCachesFiles = []

	subCacheSuffixes = [i for i in range(1, numSubCaches + 1)]
	subCacheSuffixes.append("symbols")
	for cacheSuffix in subCacheSuffixes:
		subCachePath = f"{mainCachePath}.{cacheSuffix}"
		cacheFileObject = open(subCachePath, mode="rb")
		cacheFileCtx = FileContext(cacheFileObject)

		subCaches.append(cacheFileCtx)
		subCachesFiles.append(cacheFileObject)
		pass

	return subCaches, subCachesFiles


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
		dyldFileCtx = FileContext(f)
		dyldCtx = DyldContext(dyldFileCtx)

		subCacheFiles: List[BinaryIO] = []
		try:
			# add sub caches if there are any
			if dyldCtx.hasSubCaches():
				subCacheFileCtxs, subCacheFiles = _openSubCaches(
					dyldPath,
					dyldCtx.header.numSubCaches
				)
				dyldCtx.addSubCaches(subCacheFileCtxs)
				pass

			machoOffset, context = dyldCtx.convertAddr(
				dyldCtx.images[imageIndex].address
			)
			machoCtx = MachOContext(
				context.fileCtx.makeCopy(copyMode=True),
				machoOffset
			)

			# Add sub caches if necessary
			if dyldCtx.hasSubCaches():
				mappings = dyldCtx.mappings
				mainFileMap = next(
					(mapping[0] for mapping in mappings if mapping[1] == context)
				)
				machoCtx.addSubfiles(
					mainFileMap,
					((m, ctx.fileCtx.makeCopy(copyMode=True)) for m, ctx in mappings)
				)
				pass

			extractionCtx = ExtractionContext(
				dyldCtx,
				machoCtx,
				_DummyProgressBar(),
				logger
			)

			# TODO: implement a way to select convertors
			slide_info.processSlideInfo(extractionCtx)
			linkedit_optimizer.optimizeLinkedit(extractionCtx)
			stub_fixer.fixStubs(extractionCtx)
			objc_fixer.fixObjC(extractionCtx)
			macho_offset.optimizeOffsets(extractionCtx)

		except Exception as e:
			logger.exception(e)
			pass

		finally:
			for file in subCacheFiles:
				file.close()
				pass
			pass
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
	parser.add_argument(
		"-j", "--jobs", type=int, default=mp.cpu_count(),
		help="Number of jobs to run simultaneously."  # noqa
	)
	args = parser.parse_args(namespace=_DyldExtractorArgs)

	# create a list of images
	images: List[str] = []
	with open(args.dyld_path, "rb") as f:
		dyldFileCtx = FileContext(f)
		dyldCtx = DyldContext(dyldFileCtx)

		for index, image in enumerate(dyldCtx.images):
			imagePath = dyldCtx.fileCtx.readString(image.pathFileOffset)[0:-1]
			imagePath = imagePath.decode("utf-8")
			imageName = imagePath.split("/")[-1]

			images.append(imageName)
		pass

	summary = ""
	with mp.Pool(args.jobs, initializer=_workerInitializer) as pool:
		# create jobs for each image
		jobs: List[Tuple[str, mp.pool.AsyncResult]] = []
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
