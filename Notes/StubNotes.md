### arm64
* original Stub call process
	1. call site
		* bl -> __TEXT.__stubs
	2. __TEXT.__stubs
		1. ldr <- __DATA.__la_symbol_ptr
		2. br ldr -> __TEXT.__stub_helper
	3. __TEXT.__stub_helper
		1. ldr <- (Stub Data)
		2. b -> dyld_stub_binder

* optimized Stub call process
	* optimized stub
		* adrp, add, br
	* non-optimized stub
		* adrp, add, br
		* still points to __la_symbol_ptr

### arm64e
* notes
	* no longer seems to use LC_DYLD_INFO
	* uses Chained fixups, but are removed in LinkeditOptimizer

### Fixing process