# PASSFuzz

## Installation
* PASSFuzz depends on a kernel module named NoDrop. 
First, run NoDrop/scripts/getmusl.sh to get musl.
Then enter NoDrop/build and use cmake to install:
```
cmake ..
make load
```
* Use make to compile afl-sys-demo. 
If you need some debugging information, turn on debug mode with: 
```
make debug=1
```
and logs will reside in afl-sys-demo/logs/logging.

## Usage
* The usage of PASSFuzz is mostly the same as AFL, some other options of PASSFuzz will later be explained.
* Note that the paths on PASSFuzz' panel refer to the number of syscall paths, not traditional paths.

