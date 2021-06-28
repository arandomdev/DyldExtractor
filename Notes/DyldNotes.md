## SharedCacheBuilder.cpp
* Call order (832.7.3)
	* 905, SharedCacheBuilder::build
		* 1024, buildImageArray()
		* 1032, optimizeObjC()
		* 1050, optimizeAwayStubs()
		* 1056, fipsSign()
		* 1071, optimizeLinkedit(), Done
		* 1075, addImageArray()
		* 1084, addOtherImageArray()
		* 1090, addClosures()
		* 1128, emitConstantObjects()
		* 1134, [Slide info], Done

---

### void SharedCacheBuilder::optimizeObjC();
* call order
	* 1630, doOptimizeObjC();
		* 1500, optimize selector loading
* Notes
	* __DATA == __DATA_CONST == __DATA_DIRTY
	* just walk classes?

---

### void CacheBuilder::optimizeAwayStubs();
* Call order
	* OptimizerBranches.cpp
		* 886, bypassStubs();
			* 933, buildStubMap();
			* 937, optimizeCallSites();

---

### void SharedCacheBuilder::fipsSign();
* Only effects libcorecrypto.dylib's hash.

---

### void CacheBuilder::optimizeLinkedit()
* Call order
	* OptimizerLinkedit.cpp
		* 914, LinkeditOptimizer::optimizeLinkedit();
			* 902, mergeLinkedits();
				* 733, copyWeakBindingInfo();
				* 740, copyExportInfo();
				* 752, copyBindingInfo();
				* 762, copyLazyBindingInfo();
				* 781, copyLocalSymbols();
				* 784, copyExportedSymbols();
				* 787, copyImportedSymbols();
				* 796, copyFunctionStarts();
				* 803, copyDataInCode();
				* 809, copyIndirectSymbolTable();
				* 817, copyPoolAndUpdateOffsets();
				* 861, copyPoolAndUpdateOffsets();

* Effected items
	* symtab command
	* dysymtab command
	* dyld info
	* function starts
	* data in code

* effected symbols
	* local symbols
	* exported symbols
	* imported symbols
	* indirect symbols


---

### void SharedCacheBuilder::addImageArray();
* ?? I don't think this changes dylibs in anyway...

---

### void SharedCacheBuilder::addOtherImageArray();
* ?? I don't think this changes dylibs in anyway...

---

### void SharedCacheBuilder::addClosures();
* ?? I don't think this changes dylibs in anyway...

---

### void SharedCacheBuilder::emitConstantObjects();
* Re-points the isa in CFString structs, i think.