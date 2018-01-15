# The imPENNetrables

## Requirements
These are the current dependencies with snippet to install on Ubuntu:

```
sudo apt-get update
sudo apt-get install \
        build-essential \
        cmake \
        libssl-dev \
        openssl 
```

## How to build with CMake

All the binaries will be generated in `bin/` folder of the source root of the repository.
We also don't use the conventional `build/` folder for CMake cache as it's reserved for BIBIFI submission.

### Bank

This snippet assumes you're at the source root of the repository.

```
mkdir -p tmp
cd tmp
cmake ..
make bank
```

### ATM

This snippet assumes you're at the source root of the repository.

```
mkdir -p tmp
cd tmp
cmake ..
make atm
```

## Notes

1. Put all the static/default variables in `src/common/config.h`
2. Put all the shared types/enums in `src/common/types.h`
3. Add/Use error codes in `src/common/config.h` to standardize return value