

DYLD_CACHE_SLIDE_PAGE_ATTRS = 0xC000 			# high bits of uint16_t are flags
DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA = 0x8000 		# index is into extras array (not starts array)
DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE = 0x4000 	# page has no rebasing
DYLD_CACHE_SLIDE_PAGE_ATTR_END = 0x8000 		# last chain entry for page

DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE = 0xFFFF  # page has no rebasing
