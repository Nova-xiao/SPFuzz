# AFL-SYS

## Installation
* AFL-SYS depends on a kernel module named NoDrop. Enter NoDrop/build and use cmake to install:
```
cmake ..
make load
```
* Use make to compile afl-sys-demo. 
If you need some debugging information, turn on debug mode with: `make debug=1`, and logs will reside in afl-sys-demo/logs/logging

