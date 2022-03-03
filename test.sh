echo core >/proc/sys/kernel/core_pattern;
insmod /home/xjf/afl-sys/kprobes/modules.ko;
./afl-fuzz -i ../test/inputs/ -o ../test/output/ ../test/toTest;
