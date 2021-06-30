import argparse
import mmap
import pathlib
import sys
import multiprocessing
import signal

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
	output: pathlib.Path
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


def _workerInitializer():
	"""
	Ignore KeyboardInterrupt in workers so that the main process
	can receive it and stop everything.
	"""
	signal.signal(signal.SIGINT, signal.SIG_IGN)
	pass


def _extractImage(
	dyldPath: pathlib.Path,
	outputDir: pathlib.Path,
	imageIndex: int,
	imagePath: str
) -> str:
	# convert imagePath to a relative path
	if imagePath[0] == "/":
		imagePath = imagePath[1:]
		pass

	outputPath = outputDir / imagePath
	print(outputPath)
	pass


def _main() -> None:
	argParser = _createArgParser()
	args = argParser.parse_args(namespace=_DyldExtractorArgs())

	# Make the output dir
	if args.output is None:
		outputDir = pathlib.Path("binaries")
		pass
	else:
		outputDir = pathlib.Path(args.output)
		pass

	outputDir.mkdir(parents=True, exist_ok=True)

	# create a list of image paths
	imagePaths: list[str] = []
	with open(args.dyld_path, "rb") as f:
		dyldFile = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
		dyldCtx = DyldContext(dyldFile)

		for image in dyldCtx.images:
			imagePath = dyldCtx.readString(image.pathFileOffset)[0:-1].decode("utf-8")
			imagePaths.append(imagePath)
			break
			pass
		pass

	with multiprocessing.Pool(initializer=_workerInitializer) as pool:
		# Create a job for each image
		jobs: list[tuple[str, multiprocessing.pool.AsyncResult]] = []
		for i, imagePath in enumerate(imagePaths):
			# The index should correspond with its index in the DSC
			jobs.append(
				(
					imagePath,
					pool.apply_async(_extractImage, (args.dyld_path, outputDir, i, imagePath))
				)
			)

			# setup a progress bar
			jobsComplete = 0
			progressBar = progressbar.ProgressBar(
				max_value=len(jobs),
				redirect_stdout=True
			)
			pass

		# Record potential logging output for each job
		jobOutputs: list[str] = []

		# wait for all jobs
		while len(jobs):
			for i in reversed(range(len(jobs))):
				imagePath, job = jobs[i]
				if job.ready():
					jobs.pop(i)

					jobsComplete += 1
					progressBar.update(jobsComplete)

					imageName = imagePath.split("/")[-1]
					print(f"Processed: {imageName}")

					jobOutput = job.get()
					if jobOutput:
						summary = f"----- {imageName} -----\n{jobOutput}--------------------\n"
						jobOutputs.append(summary)
						print(summary)
						pass
					pass
				pass
			pass

		# close the pool and cleanup
		pool.close()
		pool.join()
		progressBar.update(jobsComplete)

		# reprint any job output
		print("\n\n----- Summary -----")
		print("".join(jobOutputs))
		print("-------------------\n\n")
		pass
	pass


if __name__ == "__main__":
	_main()
