# DyldExtractor
Extract Binaries from Apple's Dyld Shared Cache to be useful in a disassembler.

# Installation

```
python3 -m pip install dyldextractor
```

# Usage Examples

```

# Listing Framework names containing <Filter Text>
dyldex -l -f <Filter Text> [dyld_shared_cache_path]

# Extracting a framework
dyldex -e SpringBoard.framework\SpringBoard [dyld_shared_cache_path]

# Extracting all frameworks/libraries from a shared cache
dyldex_all [dyld_shared_cache_path]

```

# Contributing
For people that want to contribute to this, here are some links for reference. Also, look at Explanations.md for in depth information about this project.

### Objective-C Runtime
* https://opensource.apple.com/source/xnu/xnu-7195.81.3/EXTERNAL_HEADERS/mach-o/loader.h.auto.html
* https://opensource.apple.com/source/objc4/objc4-781/runtime/objc-runtime-new.h.auto.html

### DYLD Cache
* https://opensource.apple.com/source/dyld/dyld-832.7.3/dyld3/shared-cache/dyld_cache_format.h.auto.html
* https://opensource.apple.com/source/dyld/dyld-832.7.3/dyld3/shared-cache/dsc_extractor.cpp.auto.html

### Other Extractors
* https://github.com/deepinstinct/dsc_fix/blob/master/dsc_fix.py
* https://github.com/kennytm/Miscellaneous/blob/master/dyld_decache.cpp
* https://github.com/phoenix3200/decache/blob/master/decache.mm

### Another extractor and a blog about DYLD extraction
* https://worthdoingbadly.com/dscextract/
* https://github.com/zhuowei/dsc_extractor_badly/blob/master/launch-cache/dsc_extractor.cpp

### Arm64 Instruction Set
* Search "DDI_0596_ARM_a64_instruction_set_architecture"
