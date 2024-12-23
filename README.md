[![PyPI version](https://badge.fury.io/py/dyldextractor.svg)](https://badge.fury.io/py/dyldextractor)
# DyldExtractor
Extract Binaries from Apple's Dyld Shared Cache to be useful in a disassembler. This tool only supports iOS, arm64.

# Installation

```
pip3 install git+https://github.com/donato-fiore/DyldExtractor.git@iOS-18-Support
```

# Usage Examples

```

# Listing Framework names containing <Filter Text>
dyldex -l -f <Filter Text> [dyld_shared_cache_path]

# Extracting a framework
dyldex -e SpringBoard.framework/SpringBoard [dyld_shared_cache_path]

# Extracting all frameworks/libraries from a shared cache
dyldex_all [dyld_shared_cache_path]

# Extracting all frameworks/libraries from a shared cache containing name
dyldex_all -f <Filter Text> [dyld_shared_cache_path]

# In any of the above examples, replace "dyldex" and "dyldex_all" with "kextex" and "kextex_all" respectively to extract images from a MH_FILESET kernelcache instead of a DSC

```
