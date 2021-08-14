# DyldExtractor
Extract Binaries from Apple's Dyld Shared Cache to be useful in a disassembler.

## Examples
```
# To look for an image
python .\dyldex.py -l -f SpringBoard DSC_File

# To extract an image
python .\dyldex.py -e SpringBoard.framework\SpringBoard DSC_File
```

# Dependencies
* python >= 3.9.5
* progressbar2, https://pypi.org/project/progressbar2/
* Has only been tested on iOS 13.5 and 14.4 caches

# Explanation
The Dyld Shared Cache (DSC) is Apple's method of optimizing the loading of system libraries (images). They do this by analyzing and combining the images in a way that it bypasses a lot of processes. This extractor uses several convertors that aim to reverse the optimization done so that images can be reverse engineered easier. The order that these convertors are run is in reverse order of the optimization done.

The goal of this project is not to make runnable files! When the DSC was built, important data was removed. Without this data we cannot completely reverse the optimizations done. We could technically try it, but there would be a very high chance of failures, and would make the extractor extremely fragile against new caches.

## slide_info.processSlideInfo()
Dynamic libraries need to be moved in memory. On normal libraries they use a table of rebase information that locate all the pointers in the file. In the DSC apple replaces this information with a linked list of rebase information, where each pointer has extra bit information to locate the next pointer. Unfortunately, this makes pointers look like "0x20XXXXXXXXXX" which breaks most disassemblers. This convertor walks down this linked list and restores the pointers to regular plain pointers. Additionally, on arm64e, it removes the pointer authentication bits, which also help disassemblers.

## linkedit_optimizer.optimizeLinkedit()
One of these optimizations involves combining the Linkedit of all images into one big linkedit. While we don't technically need to re-split the Linkedit, it allows for faster disassembly and smaller file sizes. This convertor is almost a one-to-one copy of Apple's "OptimizerLinkedit", just with the opposite result.

## Stub_fixer.fixStubs()
In the DSC stubs are bypassed. In normal images, stubs generally work like this.

1. Code in the __text section calls the stub for objc_msgSend.
2. The stub loads and jumps to its symbol pointer, which currently pointers to a stub helper.
3. The stub helper calls the dyld binder which changes the symbol pointer to the actual objc_msgSend function. And then jumps to objc_msgSend.
4. All future calls to the stub will load and jump to the objc_msgSend function.

But in the DSC the code is modified to either the two following cases.

1. The code jumps to the function directly.
2. The code jumps to one or more "trampoline" stubs, which eventually lands on the function.

To reverse this we need to symbolize each element of the stub process and relink them together.

## Objc_fixer.fixObjC()
A majority of Objective-C structures and data are moved out of the images themselves and put into libobjc's file. We can visit each pointer in classlist, protolist, catlist, etc, to almost recursively pull in all the ObjC data again. Similar to what Apple does, all the data is put into one big segment.

Also, ObjC uses selectors to call on methods. In the DSC all the selectors are combined, and all the instructions that used the original selector reference pointers are changed to just directly load the string. This also needs to be reversed, whether by relinking the instruction back to the selector pointer, or by pointing the load address to a string that's inside the image.

## Macho_offset.optimizeOffsets()
Because the actual segments of the image are split across large distances, the resulting output file would be gigabytes big, with most of it being unused space. This changes the file offsets so that the output file is much smaller. Note, this does not change the VM Addresses as that would break PC relative instructions and pointers.

# Contributing
For people that want to contribute to this, here are some links for reference.

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