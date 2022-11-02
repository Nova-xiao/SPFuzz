# AFL-SYS

## Installation
* AFL-SYS depends on a kernel module named NoDrop. 
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
* The usage of AFL-SYS is exactly the same with AFL, some other options of AFL-SYS will later be explained.
* Note that the paths on AFL-SYS' panel refers to the number of syscall n-grams, not traditional paths.

