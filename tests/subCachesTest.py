import mmap

from typing import List, Tuple, BinaryIO

from DyldExtractor.dyld.dyld_context import DyldContext
from DyldExtractor.dyld.dyld_structs import dyld_cache_mapping_and_slide_info
from DyldExtractor.file_context import FileContext


MAIN_CACHE_PATH = "binaries\\caches\\DSC_iPhoneX_10,3_iOS15.1\\dyld_shared_cache_arm64"  # noqa


def openSubCaches(
	mainCachePath: str,
	numSubCaches: int
) -> List[Tuple[FileContext, BinaryIO]]:
	"""Create FileContext objects for each sub cache.

	Assumes that each sub cache has the same base name as the
	main cache, and that the suffixes are preserved.

	Also opens the symbols cache, and adds it to the end of
	the list.

	Returns:
		A list of subcaches, and their file objects, which must be closed!
	"""
	subCaches = []

	subCacheSuffixes = [i for i in range(1, numSubCaches + 1)]
	subCacheSuffixes.append("symbols")
	for cacheSuffix in subCacheSuffixes:
		subCachePath = f"{mainCachePath}.{cacheSuffix}"
		cacheFileObject = open(subCachePath, mode="rb")
		cacheMap = mmap.mmap(cacheFileObject.fileno(), 0, access=mmap.ACCESS_READ)
		cacheFile = FileContext(cacheMap)

		subCaches.append((cacheFile, cacheFileObject))
		pass

	return subCaches


def main():
	with open(MAIN_CACHE_PATH, mode="rb") as f:
		mainCache = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
		mainCacheFile = FileContext(mainCache)

		dyldCtx = DyldContext(mainCacheFile)
		if dyldCtx.hasSubCaches():
			subCaches = openSubCaches(
				MAIN_CACHE_PATH,
				dyldCtx.header.numSubCaches
			)
			# TODO: close files
			dyldCtx.addSubCaches([subCache[0] for subCache in subCaches])
			pass

		print("Main Cache")
		print(dyldCtx.mappings[0])
		print()
		for i, subCache in enumerate(dyldCtx._subCaches):
			print(i + 1)
			[print(mapping) for mapping in subCache.mappings]
			assert subCache.header.mappingCount == subCache.header.mappingWithSlideCount
			print()
	pass


if __name__ == "__main__":
	main()
	pass
