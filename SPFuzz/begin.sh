echo core >/proc/sys/kernel/core_pattern;

#./afl-fuzz -i ../gcctest/inputs/ -o ../gcctest/output/ ../gcctest/gcc-10.1.0/bin/toTest -o ../gcctest/output/null;
#./afl-fuzz -i ../gcctest/inputs/ -o ../gcctest/output/ -Q ../gcctest/gcc-10.1.0/bin/toTest -o ../gcctest/output/null;

# stochfuzz
./afl-fuzz -i ../gzipTest/inputs -o ../gzipTest/output-s -t 1000 ../gzipTest/gzip-s.phantom -c -k -d -v @@

./afl-fuzz -i ../gzipTest/inputs -o ../gzipTest/output-afl -t 1000 ../gzipTest/gzip-1.12/aflbuild/gzip -c -k -d -v @@
./afl-fuzz -i ../gzipTest/inputs -o ../gzipTest/output-time -t 1000 ../gzipTest/toTest -c -k -d -v @@
./afl-fuzz -i ../gzipTest/inputs -o ../gzipTest/output -P ../gzipTest/gzip-1.12/aflbuild/gzip -t 1000 ../gzipTest/toTest -c -k -d @@
./afl-fuzz -i ../gzipTest/inputs -o ../gzipTest/output1 -t 1000 ../gzipTest/gzip-1.12/aflbuild/gzip -c -k -d @@
./afl-fuzz -i ../gzipTest/inputs -o ../gzipTest/output1 -n -t 1000 ../gzipTest/gzip-1.12/aflbuild/gzip -c -k -d @@
# grams
./afl-fuzz -i ../gzipTest/inputs -o ../gzipTest/output-32 -t 1000 -- ../gzipTest/toTest -c -k -d -v @@


./afl-fuzz -i ../sqliteTest/aflQinputs -o ../sqliteTest/output1 ../sqliteTest/toTest -bail @@
afl-fuzz -i ../sqliteTest/aflQinputs -o ../sqliteTest/output ../sqliteTest/sqliteAFL/build/sqlite3 -bail @@

# # sqlite with coverage measurement
# afl-cov -d /root/xjf/sqliteTest/output1 --live --coverage-cmd \
# "cat AFL_FILE | /root/xjf/sqliteTest/sqliteCov/build/sqlite3 -bail" \
# --code-dir /root/xjf/sqliteTest/sqliteCov/build/

# ./afl-fuzz -i ../curlTest/inputs -o ../curlTest/output1 ../curlTest/toTest

./afl-fuzz -m 5000 -i ~/xpdfTest/inputs -o ~/xpdfTest/output-1day-time -- ~/xpdfTest/toTest @@ ~/xpdfTest/out/null
./afl-fuzz -i ../xpdfTest/inputs/ -o ../xpdfTest/output-a-time -- ~/xpdfTest/aflbuild/xpdf/pdftotext @@ ../xpdfTest/out/null 
./afl-fuzz -t 5000 -m 5000 -i ~/xpdfTest/inputs -o ~/xpdfTest/output-q-1day -Q ~/xpdfTest/build/pdftotext @@ ~/xpdfTest/out/null
./afl-fuzz -i ../xpdfTest/inputs/ -o ../xpdfTest/output1 ../xpdfTest/build/xpdf/pdftotext @@ ../xpdfTest/out/null 
# ./afl-fuzz -i ../xpdfTest/inputs/ -o ../xpdfTest/output2 -n ../xpdfTest/build/xpdf/pdftotext @@ ../xpdfTest/out/null 
./afl-fuzz -m none -i ~/xpdfTest/inputs -o ~/relationTest/xpdf/output ~/xpdfTest/toTest @@ ~/xpdfTest/out/null
# stochfuzz
./afl-fuzz -t 5000 -i ../xpdfTest/inputs -o ../xpdfTest/output-s ../xpdfTest/build/pdftotext-s.phantom @@ ../xpdfTest/out/null 

./afl-fuzz -m none -i ~/xpdfTest/inputs -o ~/xpdfTest/output-32 -- ~/xpdfTest/toTest @@ ~/xpdfTest/out/null


LD_PRELOAD=~/nginxTest/preeny/x86_64-linux-gnu/desock.so ./afl-fuzz -i ~/nginxTest/inputs1 -o ~/nginxTest/output-time -m 1000 ~/nginxTest/toTest 
LD_PRELOAD=~/nginxTest/preeny/x86_64-linux-gnu/desock.so afl-fuzz -i ~/nginxTest/inputs1 -o ~/nginxTest/output-afl -m 1000 ~/nginxTest/aflbuild/sbin/nginx


sudo rm -r -f ../xpdfTest/output/*
../xpdfTest/toTest ../xpdfTest/inputs/helloworld.pdf ../xpdfTest/out/null

#compare AFL and AFL-SYS in tuples
./afl-fuzz -P ../xpdfTest/build/xpdf/pdftotext \
-i ../xpdfTest/inputs -o ../xpdfTest/output \
../xpdfTest/toTest @@ ../xpdfTest/out/null

# compile lib hooking 
gcc /home/xjf/funchook/allfile-hooking.c -o /home/xjf/funchook/hooking.so -fPIC -shared -ldl -D_GNU_SOURCE
# lib hooking test
LD_PRELOAD=/home/xjf/funchook/hooking.so /home/xjf/gzipTest/gzip-1.12/gzip -c -k -d ./inputs/tarfile.tgz
LD_PRELOAD=/home/xjf/funchook/hooking.so /home/xjf/xpdfTest/build/xpdf/pdftotext /home/xjf/xpdfTest/inputs/helloworld.pdf /home/xjf/xpdfTest/out/null


# v8
./afl-fuzz -i /data/zzx/Coding/software/v8/input -o /data/zzx/Coding/software/v8/output /data/zzx/Coding/software/v8/v8bin/toTest @@
# python
./afl-fuzz -i ../python_test/input -o ../python_test/output ../python_test/toTest @@

# tcpdump with asan
./afl-fuzz -m none -i ~/tcpdumpTest/inputs -o ~/tcpdumpTest/output -- ~/tcpdumpTest/asanbuild/toTest -vvvvXX -ee -nn -r @@
# ...without asan
afl-fuzz -t 5000 -m none -i /home/xjf/tcpdumpTest/inputs -o /home/xjf/tcpdumpTest/output-afl -- ~/tcpdumpTest/aflbuild/bin/tcpdump -vvvvXX -ee -nn -r @@
./afl-fuzz -m none -i ~/tcpdumpTest/inputs -o ~/tcpdumpTest/output-time -- ~/tcpdumpTest/build/toTest -vvvvXX -ee -nn -r @@
./afl-fuzz -m none -i ~/tcpdumpTest/inputs -o ~/tcpdumpTest/output1 -- ~/tcpdumpTest/build/toTest -vvvvXX -ee -nn -r @@
./afl-fuzz -t 5000 -m none -i ~/tcpdumpTest/inputs -o ~/tcpdumpTest/output1 -Q -- ~/tcpdumpTest/build/bin/tcpdump -vvvvXX -ee -nn -r @@
# Stochfuzz
./afl-fuzz -m none -i ~/tcpdumpTest/inputs -o ~/tcpdumpTest/output-s -- ~/tcpdumpTest/build/tcpdump-s.phantom -vvvvXX -ee -nn -r @@
# ...with obfuscator
./afl-fuzz -m none -i ~/tcpdumpTest/inputs -o ~/tcpdumpTest/output-ob -- ~/tcpdumpTest/obuild/toTest -vvvvXX -ee -nn -r @@
# afl
afl-fuzz -t 5000 -m none -i ~/tcpdumpTest/inputs -o ~/tcpdumpTest/output-afl -- ~/tcpdumpTest/aflbuild/bin/tcpdump -vvvvXX -ee -nn -r @@
# grams
./afl-fuzz -m none -t 5000 -i ~/tcpdumpTest/inputs -o ~/tcpdumpTest/output-32 -- ~/tcpdumpTest/asanbuild/toTest -vvvvXX -ee -nn -r @@
./afl-fuzz -m none -t 5000 -i ~/tcpdumpTest/inputs -o ~/tcpdumpTest/output-n -- ~/tcpdumpTest/asanbuild/toTest -vvvvXX -ee -nn -r @@



# nginx grams
./afl-fuzz -i ~/nginxTest/inputs1 -o ~/nginxTest/output-32 -m 1000 -- ~/nginxTest/toTest @@



# readelf
./afl-fuzz -i ~/readelfTest/small-inputs -o ~/readelfTest/output-1day -- ~/readelfTest/build/toTest -a @@
./afl-fuzz -i ~/readelfTest/small-inputs -o ~/readelfTest/output-1day-time -- ~/readelfTest/build/toTest -a @@
./afl-fuzz -m 5000 -i ~/readelfTest/small-inputs -o ~/readelfTest/output-q-1day -Q -- ~/readelfTest/build/readelf -a @@
./afl-fuzz -i ~/readelfTest/inputs -o ~/readelfTest/output-zafl1 -- ~/readelfTest/build/readelf.zafl -a @@
# stochfuzz
./afl-fuzz -i ~/readelfTest/inputs -o ~/readelfTest/output-s -- ~/readelfTest/build/readelf-s.phantom -a @@

# grams
./afl-fuzz -i ~/readelfTest/small-inputs -o ~/readelfTest/output-32 -- ~/readelfTest/build/toTest -a @@



# sfconvert 
./afl-fuzz -t 5000 -i ~/sfconvertTest/inputs -o ~/sfconvertTest/output -- ~/sfconvertTest/bin/toTest @@ out format next channels 2 integer 16 2scomp
./afl-fuzz -m 20000 -t 5000 -i ~/sfconvertTest/inputs -o ~/sfconvertTest/output-q -Q -- ~/sfconvertTest/bin/sfconvert @@ out2 format next channels 2 integer 16 2scomp

# unrtf 
./afl-fuzz -i ~/unrtfTest/inputs -o ~/unrtfTest/output -- ~/unrtfTest/build/toTest --verbose --html --nopict @@
./afl-fuzz -m none -i ~/unrtfTest/inputs -o ~/unrtfTest/output-q-1day -Q -- ~/unrtfTest/build/unrtf --verbose --html --nopict @@


# nconvert
./afl-fuzz -i ~/nconvertTest/inputs -o ~/nconvertTest/output -- ~/nconvertTest/toTest -resize 50%x50% -rotate 270 -contrast -debug All @@ out.jpg
./afl-fuzz -i ~/nconvertTest/small-inputs -o ~/nconvertTest/output -- ~/nconvertTest/toTest @@ out.jpg
# ./afl-fuzz -m none -t 5000 -i ~/nconvertTest/inputs -o ~/nconvertTest/output-q -Q -- ~/nconvertTest/convert -resize 50%x50% -rotate 270 -contrast -debug All @@ out1.jpg
./afl-fuzz -m 5000 -t 5000 -i ~/nconvertTest/small-inputs -o ~/nconvertTest/output-q -Q -- ~/nconvertTest/convert @@ out1.jpg

# pngout
./afl-fuzz -i ~/pngoutTest/inputs -o ~/pngoutTest/output -- ../pngoutTest/toTest @@ -c2 -f3 -b128 -kbKGD -v
./afl-fuzz -m none -t 5000 -i ~/pngoutTest/inputs -o ~/pngoutTest/output-q -Q -- ~/pngoutTest/pngout @@ -c2 -f3 -b128 -kbKGD -v

# winrar
./afl-fuzz -i ~/winrarTest/inputs -o ~/winrarTest/output-1day -- ~/winrarTest/bin/toTest cw -y -ierr @@
./afl-fuzz -m 1000 -t 5000 -i ~/winrarTest/inputs -o ~/winrarTest/output-q-1day -Q -- ~/winrarTest/bin/rar cw -y -ierr @@


# # adobe reader ( /opt/Adobe/Reader9/Reader/intellinux/bin/acroread )
# ACRO_INSTALL_DIR=/opt/Adobe/Reader9/Reader ACRO_CONFIG=intellinux LD_LIBRARY_PATH=$LD_LIBRARY_PATH:'/opt/Adobe/Reader9/Reader/intellinux/lib' ./afl-fuzz -i ~/adbrTest/inputs -o ~/adbrTest/output -- ~/adbrTest/toTest --toPostScript @@ 

# unrar
./afl-fuzz -i ~/unrarTest/inputs -o ~/unrarTest/output -- ~/unrarTest/bin/toTest lpv @@
./afl-fuzz -i ~/unrarTest/inputs -o ~/unrarTest/output-time -- ~/unrarTest/bin/toTest lpv @@
./afl-fuzz -m 5000 -t 2000 -i ~/unrarTest/inputs -o ~/unrarTest/output-q -Q -- ~/unrarTest/bin/unrar lpv @@
# grams
./afl-fuzz -i ~/unrarTest/inputs -o ~/unrarTest/output-32 -- ~/unrarTest/bin/toTest lpv @@


# nvdisasm
./afl-fuzz -m 5000 -t 2000 -i ~/nvdisasmTest/inputs -o ~/nvdisasmTest/output-1day -- ~/nvdisasmTest/bin/toTest -sf @@
./afl-fuzz -m 5000 -t 5000 -i ~/nvdisasmTest/inputs -o ~/nvdisasmTest/output-q-1day -Q -- ~/nvdisasmTest/bin/nvdisasm -sf @@

# cuobjdump
# cuobjdump -symbols -elf -ptx -sass inputs/addWithCuda.cubin
./afl-fuzz -m 5000 -t 2000 -i ~/cuobjdumpTest/inputs -o ~/cuobjdumpTest/output -- ~/cuobjdumpTest/bin/toTest -symbols -elf -ptx -sass @@
./afl-fuzz -m 5000 -t 2000 -i ~/cuobjdumpTest/inputs -o ~/cuobjdumpTest/output-q -Q -- ~/cuobjdumpTest/bin/cuobjdump -symbols -elf -ptx -sass @@

# # cu++filt
# # nm inputs/addWithCuda.cubin | /usr/local/cuda-11.6/bin/cu++filt
# ./afl-fuzz -m 5000 -t 2000 -i ~/cu++filtTest/inputs -o ~/cu++filtTest/output -- ~/cu++filtTest/bin/toTest 

# bin2c
./afl-fuzz -m 5000 -t 5000 -i ~/bin2cTest/inputs -o ~/bin2cTest/output -- ~/bin2cTest/bin/toTest @@
./afl-fuzz -m 5000 -t 5000 -i ~/bin2cTest/inputs -o ~/bin2cTest/output-q -Q -- ~/bin2cTest/bin/bin2c @@

# flvmeta(remove)
# ./afl-fuzz -i ~/archieve/flvmeta/newfuzzing/sys/in -o ~/archieve/flvmeta/newfuzzing/sys/out -- ~/archieve/flvmeta/fuzzing/sys/toTest @@
# ./afl-fuzz -i ~/archieve/flvmeta/newfuzzing/qemu/in -o ~/archieve/flvmeta/newfuzzing/qemu/out -Q -- ~/archieve/flvmeta/fuzzing/qemu/flvmeta @@
# afl-fuzz -i ~/archieve/flvmeta/fuzzing/sys/in -o ~/archieve/flvmeta/aflbuild/out -- ~/archieve/flvmeta/aflbuild/flvmeta @@

# cert-basic(remove)
# ./afl-fuzz -i ~/archieve/certbasic-libksba-libksba-1.3.4/newfuzzing/in -o ~/archieve/certbasic-libksba-libksba-1.3.4/newfuzzing/qemu/out -Q -- ~/archieve/certbasic-libksba-libksba-1.3.4/newfuzzing/qemu/cert-basic @@
# afl-fuzz -i ~/archieve/certbasic-libksba-libksba-1.3.4/newfuzzing/in -o ~/archieve/certbasic-libksba-libksba-1.3.4/newfuzzing/out -- ~/archieve/certbasic-libksba-libksba-1.3.4/tests/cert-basic @@

# zola
~/zolaTest/bin/toTest -r /home/xjf/zolaTest/zolaout/ -c /home/xjf/zolaTest/configs/config-hello-rust.toml build
./afl-fuzz -m 5000 -t 5000 -i ~/zolaTest/configs -o ~/zolaTest/output-time -- ~/zolaTest/bin/toTest -r /home/xjf/zolaTest/zolaout/ -c @@ build
./afl-fuzz -i ~/zolaTest/configs -o ~/zolaTest/output-q -Q -- ~/zolaTest/bin/zola -r /home/xjf/zolaTest/zolaout/ -c @@ build
./afl-fuzz -i ~/zolaTest/configs -o ~/zolaTest/output-a-time -Q -- ~/zolaTest/bin/zola -r ~/zolaTest/zolaout/ -c @@ build

# grams
./afl-fuzz -m 5000 -t 5000 -i ~/zolaTest/configs -o ~/zolaTest/output-32 -- ~/zolaTest/bin/toTest -r /home/xjf/zolaTest/zolaout/ -c @@ build


# z3
~/z3Test/toTest -v:5 ~/z3Test/inputs/input22.txt
./afl-fuzz -i ~/z3Test/inputs -o ~/z3Test/output-time -- ~/z3Test/toTest -v:5 @@
./afl-fuzz -i ~/z3Test/inputs -o ~/z3Test/output-q -Q -- ~/z3Test/z3-q -v:5 @@
./afl-fuzz -t 5000 -i ~/z3Test/inputs -o ~/z3Test/output-a-time -Q -- ~/z3Test/z3-q -v:5 @@

# gram
./afl-fuzz -i ~/z3Test/inputs -o ~/z3Test/output-32 -- ~/z3Test/toTest -v:5 @@


# Apache httpd
patch -p0 -i fuzz-patch.diff
(sudo -s) ./bin/httpd -X -F @@
./afl-fuzz -i /home/xjf/httpdTest/small-inputs -o /home/xjf/httpdTest/output -x /home/xjf/httpdTest/http.dict -m none -t 2000 -- /home/xjf/httpdTest/bin/toTest -X -F @@
./afl-fuzz -i /home/xjf/httpdTest/small-inputs -o /home/xjf/httpdTest/output-q -x /home/xjf/httpdTest/http.dict -m 5000 -t 2000 -Q -- /home/xjf/httpdTest/bin/httpd-q -X -F @@



### MAGMA Benchmark
# lua
./afl-fuzz -m 1000 -Q -i /home/xjf/luaTest/corpus/selected -o /home/xjf/luaTest/workdir-q -- /home/xjf/luaTest/out/lua-q
./afl-fuzz -m 1000 -i /home/xjf/luaTest/corpus/selected -o /home/xjf/luaTest/workdir -- /home/xjf/luaTest/out/toTest
afl-fuzz -m 1000 -i /home/xjf/magma/targets/lua/corpus/selected -o /home/xjf/magma/targets/lua/workdir -- /home/xjf/magma/targets/lua/out/lua.afl
# stochfuzz
afl-fuzz -m 1000 -t 2000 -i ~/luaTest/corpus/selected -o ~/luaTest/workdir -- ~/luaTest/out/lua-s.phantom

# grams
./afl-fuzz -m 1000 -i /home/xjf/luaTest/corpus/selected -o /home/xjf/luaTest/output-32 -- /home/xjf/luaTest/out/toTest


# libpng
./afl-fuzz -m 1000 -Q -i /home/xjf/magma/targets/libpng/corpus/libpng_read_fuzzer -o /home/xjf/magma/targets/libpng/workdir-q -- /home/xjf/magma/targets/libpng/libpng-q
afl-fuzz -m 1000 -i /home/xjf/magma/targets/libpng/corpus/libpng_read_fuzzer -o /home/xjf/magma/targets/libpng/workdir-a -- /home/xjf/magma/targets/libpng/libpng.afl
./afl-fuzz -m 1000 -i /home/xjf/libpngTest/corpus/libpng_read_fuzzer -o /home/xjf/libpngTest/workdir -- /home/xjf/libpngTest/out/toTest


# openssl:server
./afl-fuzz -m 5000 -Q -i /home/xjf/magma/targets/openssl/corpus/server -o /home/xjf/magma/targets/openssl/workdir-server-q -- /home/xjf/magma/targets/openssl/bin/server
./afl-fuzz -m 5000 -i /home/xjf/magma/targets/openssl/corpus/server -o /home/xjf/magma/targets/openssl/workdir-server -- /home/xjf/magma/targets/openssl/bin/toTest

# sqlite3
./afl-fuzz -m 1000 -Q -i /home/xjf/magma/targets/sqlite3/corpus/sqlite3_fuzz -o /home/xjf/magma/targets/sqlite3/workdir-q -- /home/xjf/magma/targets/sqlite3/out/sqlite3-q
./afl-fuzz -m 1000 -Q -i /home/xjf/sqlite3Test/corpus/sqlite3_fuzz -o /home/xjf/sqlite3Test/workdir-q -- /home/xjf/sqlite3Test/out/sqlite3_fuzz
afl-fuzz -i /home/xjf/magma/targets/sqlite3/corpus/sqlite3_fuzz -o /home/xjf/magma/targets/sqlite3/workdir-a -- /home/xjf/magma/targets/sqlite3/out/sqlite3.afl



### wine-based apps
### New discovery: wineserver can run in persistent mode: 
###  (/opt/wine-stable/bin/wineserver -f -p -d 0) &> winelog1.txt
###  /opt/wine-stable/bin/wineserver -p

# pngout.exe
./afl-fuzz -t 5000 -m 20000 -i ~/pngoutTest/inputs -o ~/wineTest/pngout-output -- /opt/wine-stable/bin/wine ~/wineTest/exe/pngout.exe @@ -c2 -f3 -b128 -kbKGD -v

# flacout.exe
# wine exe/flacout.exe flacout-inputs/common_voice_zh-CN_34949995.flac out -y
./afl-fuzz -t 5000 -m 20000 -i ~/wineTest/flacout-inputs -o ~/wineTest/flacout-output -- /opt/wine-stable/bin/wine ~/wineTest/exe/flacout.exe @@ out -y

# pnghalf.exe
# wine exe/pnghalf.exe ../pngoutTest/inputs/xpdf-sys-cov.png out /y
./afl-fuzz -t 5000 -m 20000 -i ~/wineTest/pnghalf-inputs -o ~/wineTest/pnghalf-output -- /opt/wine-stable/bin/wine ~/wineTest/exe/pnghalf.exe @@ out /y

# winrar.exe
# wine ~/wineTest/exe/Rar.exe cw -y ~/winrarTest/inputs/1.rar
./afl-fuzz -m 5000 -t 20000 -i ~/winrarTest/inputs -o ~/wineTest/winrar-output -- /opt/wine-stable/bin/wine ~/wineTest/exe/Rar.exe cw -y -ierr @@



# honggfuzz
honggfuzz -i /home/xjf/xpdfTest/inputs --linux_perf_instr -- ~/xpdfTest/asanbuild/xpdf/pdftotext ___FILE___ ~/xpdfTest/out/null
honggfuzz -i /home/xjf/xpdfTest/inputs --linux_perf_branch -- ~/xpdfTest/asanbuild/xpdf/pdftotext ___FILE___ ~/xpdfTest/out/null

honggfuzz -i ~/z3Test/inputs -o ~/z3Test/output-h --linux_perf_instr -- ~/z3Test/z3-q -v:5 ___FILE___ 

honggfuzz -i /home/xjf/xpdfTest/inputs --linux_perf_instr -- ~/xpdfTest/asanbuild/xpdf/pdftotext ___FILE___ ~/xpdfTest/out/null

honggfuzz -i /home/xjf/tcpdumpTest/inputs --linux_perf_instr -- ~/xpdfTest/asanbuild/xpdf/pdftotext ___FILE___ ~/xpdfTest/out/null


#dump
./afl-fuzz -m none -i ~/readelfTest/small-inputs -o ~/relationTest/readelf/output -- ~/readelfTest/build/toTest @@ ~/readelfTest/out/null -a
./afl-fuzz -i ~/readelfTest/small-inputs -o ~/relationTest/readelf/output-a -- ~/readelfTest/build/readelf1.zafl @@ ~/readelfTest/out/null -a
./afl-fuzz -n -i ~/readelfTest/small-inputs -o ~/relationTest/readelf/output-d -- ~/readelfTest/build/readelf @@ ~/readelfTest/out/null -a
./afl-fuzz -t 5000 -m none -i ~/sfconvertTest/inputs -o ~/relationTest/sfconvert/output -- ~/sfconvertTest/bin/toTest @@ out format next channels 2 integer 16 2scomp
./afl-fuzz -i ~/sfconvertTest/inputs -o ~/relationTest/sfconvert/output-a -- ~/sfconvertTest/bin/sfconvert.zafl @@ out format next channels 2 integer 16 2scomp
./afl-fuzz -n -i ~/sfconvertTest/inputs -o ~/relationTest/sfconvert/output-d -- ~/sfconvertTest/bin/sfconvert @@ out format next channels 2 integer 16 2scomp
./afl-fuzz -i /home/xjf/luaTest/corpus/selected -o /home/xjf/relationTest/lua/output -- /home/xjf/luaTest/out/toTest @@
./afl-fuzz -n -i /home/xjf/luaTest/corpus/selected -o /home/xjf/relationTest/lua/output-d -- /home/xjf/luaTest/out/lua-q @@
./afl-fuzz -t 2000 -i /home/xjf/luaTest/corpus/selected -o /home/xjf/relationTest/lua/output-a -- /home/xjf/luaTest/out/lua.afl @@
./afl-fuzz -i /home/xjf/libpngTest/corpus/libpng_read_fuzzer -o /home/xjf/relationTest/libpng/output-a -- /home/xjf/libpngTest/out/libpng_read_fuzzer.afl @@
./afl-fuzz -i /home/xjf/libpngTest/corpus/libpng_read_fuzzer -o /home/xjf/relationTest/libpng/output -- /home/xjf/libpngTest/out/toTest @@
./afl-fuzz -n -i /home/xjf/libpngTest/corpus/libpng_read_fuzzer -o /home/xjf/relationTest/libpng/output-d -- /home/xjf/libpngTest/out/libpng_read_fuzzer @@


# calculate paths
python3 afl-sys-demo/test_paths_multi.py -s /data/xjf/relationTest-gzip/afl-sys-inputs/ -o /home/xjf/afl-sys-paths-test-m.txt -t /home/xjf/ -- /home/xjf/gzipTest/gzip-1.12/aflbuild/gzip -c -d -k @@ 
python afl-sys-demo/test_path_multi.py -s ~/relationTest/readelf/afl-sys-inputs -o ~/relationTest/readelf/afl-sys-paths.txt -t /home/xjf/relationTest/tmp/input -- ~/readelfTest/build/readelf.zafl @@ ~/readelfTest/out/null -a
python afl-sys-demo/test_path_multi.py -s ~/relationTest/readelf/afl-dumb-inputs -o ~/relationTest/readelf/afl-dumb-paths.txt -t /home/xjf/relationTest/tmp1/input -- ~/readelfTest/build/readelf.zafl @@ ~/readelfTest/out/null -a
python afl-sys-demo/test_path_multi.py -s ~/relationTest/lua/afl-sys-inputs -o ~/relationTest/lua/afl-sys-paths.txt -t /home/xjf/relationTest/tmp1/input -- ~/luaTest/out/lua.afl @@
python afl-sys-demo/test_path_multi.py -s ~/relationTest/lua/afl-inputs -o ~/relationTest/lua/afl-paths-test.txt -t /home/xjf/relationTest/tmp/input -- ~/luaTest/out/lua.afl @@
python afl-sys-demo/test_path_multi.py -s ~/relationTest/lua/afl-dumb-inputs -o ~/relationTest/lua/afl-dumb-paths.txt -t /home/xjf/relationTest/tmp2/input -- ~/luaTest/out/lua.afl @@
# grams
python ~/afl-sys-demo/test_path_multi.py -s ~/tcpdumpTest/output-32/queue -o ~/tcpdumpTest/output-32/paths.txt -t /home/xjf/relationTest/tmp2/input -- ~/tcpdumpTest/aflbuild/bin/tcpdump @@
python ~/afl-sys-demo/test_path_multi.py -s ~/z3Test/output-32/queue -o ~/z3Test/output-32/afl-paths.txt -t /home/xjf/relationTest/tmp2/input -- ~/ @@ out format next channels 2 integer 16 2scomp


# cov
~/afl-cov/afl-cov -d /home/xjf/relationTest/lua/afl-dumb-inputs --coverage-cmd \
"/home/xjf/luaTest/repo/lua AFL_FILE" \
--code-dir /home/xjf/luaTest/repo --lcov-web-all --overwrite --enable-branch-coverage \
> ~/relationTest/lua/afl-dumb-inputs/cov_out.txt
~/afl-cov/afl-cov -d /home/xjf/relationTest/lua/afl-sys-inputs --coverage-cmd \
"/home/xjf/luaTest/repo/lua AFL_FILE" \
--code-dir /home/xjf/luaTest/repo --lcov-web-all --overwrite --enable-branch-coverage\
> ~/relationTest/lua/afl-sys-inputs/cov_out_sys.txt
~/afl-cov/afl-cov -d /home/xjf/relationTest/lua/afl-inputs --coverage-cmd \
"/home/xjf/luaTest/repo/lua AFL_FILE" \
--code-dir /home/xjf/luaTest/repo --lcov-web-all --overwrite --enable-branch-coverage \
> ~/relationTest/lua/afl-inputs/cov_out_afl.txt



# afl-pt no Oslab
sudo grub-reboot "1>4"


# New experiments
python coverage.py -f move -s ~/xpdfTest/output-a-time/queue -d xpdf-a/
python coverage.py -f move -s ~/xpdfTest/output-a-time/queue -d xpdf-a/





# New experiments, for coverage
# honggfuzz
# CPU counting
sudo ./honggfuzz -i ~/nginxTest/inputs1 -o ~/nginxTest/output-h -n 1 --linux_perf_instr -- ~/nginxTest/build/sbin/nginx ___FILE___ 
sudo ./honggfuzz -i ~/luaTest/corpus/selected -o ~/luaTest/output-h -n 1 --linux_perf_instr -- ~/luaTest/out/lua ___FILE___ 
sudo ./honggfuzz -i ~/gzipTest/inputs -o ~/gzipTest/output-h -n 1 --linux_perf_instr -- ../gzipTest/toTest -c -k -d -v ___FILE___ 
sudo ./honggfuzz -i ~/readelfTest/small-inputs -o ~/readelfTest/output-h -n 1 --linux_perf_instr -- ~/readelfTest/build/toTest -a ___FILE___
sudo ./honggfuzz -i ~/zolaTest/configs -o ~/zolaTest/output-h -n 1 --linux_perf_instr -- ~/zolaTest/bin/toTest -r ~/zolaTest/zolaout/ -c ___FILE___  build
sudo ./honggfuzz -i ~/xpdfTest/inputs -o ~/xpdfTest/output-h -n 1 --linux_perf_instr -- ~/xpdfTest/build/xpdf/pdftotext ___FILE___ ~/xpdfTest/out/null
sudo ./honggfuzz -i ~/z3Test/inputs -o ~/z3Test/output-h -n 1 --linux_perf_instr -- ~/z3Test/z3-q -v:5 ___FILE___ 
sudo ./honggfuzz -i ~/tcpdumpTest/inputs -o ~/tcpdumpTest/output-h -n 1 --linux_perf_instr -- ~/tcpdumpTest/build/bin/tcpdump -vvvvXX -ee -nn -r ___FILE___
sudo ./honggfuzz -i ~/unrarTest/inputs -o ~/unrarTest/output-h -n 1 --linux_perf_instr -- ~/unrarTest/bin/unrar lpv ___FILE___
# intel BTS
sudo ./honggfuzz -i ~/nginxTest/inputs1 -o ~/nginxTest/output-hb -n 1 --linux_perf_bts_edge -- ~/nginxTest/build/sbin/nginx ___FILE___ 
sudo ./honggfuzz -i ~/luaTest/corpus/selected -o ~/luaTest/output-hb -n 1 --linux_perf_bts_edge -- ~/luaTest/out/lua ___FILE___ 
sudo ./honggfuzz -i ~/gzipTest/inputs -o ~/gzipTest/output-hb -n 1 --linux_perf_bts_edge -- ../gzipTest/toTest -c -k -d -v ___FILE___ 
sudo ./honggfuzz -i ~/readelfTest/small-inputs -o ~/readelfTest/output-hb -n 1 --linux_perf_bts_edge -- ~/readelfTest/build/toTest -a ___FILE___
sudo ./honggfuzz -i ~/zolaTest/configs -o ~/zolaTest/output-hb -n 1 --linux_perf_bts_edge -- ~/zolaTest/bin/toTest -r ~/zolaTest/zolaout/ -c ___FILE___  build
sudo ./honggfuzz -i ~/xpdfTest/inputs -o ~/xpdfTest/output-hb -n 1 --linux_perf_bts_edge -- ~/xpdfTest/build/xpdf/pdftotext ___FILE___ ~/xpdfTest/out/null
sudo ./honggfuzz -i ~/z3Test/inputs -o ~/z3Test/output-hb -n 1 --linux_perf_bts_edge -- ~/z3Test/z3-q -v:5 ___FILE___ 
sudo ./honggfuzz -i ~/tcpdumpTest/inputs -o ~/tcpdumpTest/output-hb -n 1 --linux_perf_bts_edge -- ~/tcpdumpTest/build/bin/tcpdump -vvvvXX -ee -nn -r ___FILE___
sudo ./honggfuzz -i ~/unrarTest/inputs -o ~/unrarTest/output-hb -n 1 --linux_perf_bts_edge -- ~/unrarTest/bin/unrar lpv ___FILE___
# intel PT
sudo ~/honggfuzz-2.5/honggfuzz -i ~/nginxTest/inputs1 -o ~/nginxTest/output-pt -n 1 --linux_perf_ipt_block -- ~/nginxTest/build/sbin/nginx ___FILE___ 
sudo ~/honggfuzz-2.5/honggfuzz -i ~/luaTest/corpus/selected -o ~/luaTest/output-pt -n 1 --linux_perf_ipt_block -- ~/luaTest/out/lua ___FILE___ 
sudo ~/honggfuzz-2.5/honggfuzz -i ~/gzipTest/inputs -o ~/gzipTest/output-pt -n 1 --linux_perf_ipt_block -- ../gzipTest/toTest -c -k -d -v ___FILE___ 
sudo ~/honggfuzz-2.5/honggfuzz -i ~/readelfTest/small-inputs -o ~/readelfTest/output-pt -n 1 --linux_perf_ipt_block -- ~/readelfTest/build/toTest -a ___FILE___
sudo ~/honggfuzz-2.5/honggfuzz -i ~/zolaTest/configs -o ~/zolaTest/output-pt -n 1 --linux_perf_ipt_block -- ~/zolaTest/bin/toTest -r ~/zolaTest/zolaout/ -c ___FILE___  build
sudo ~/honggfuzz-2.5/honggfuzz -i ~/xpdfTest/inputs -o ~/xpdfTest/output-pt -n 1 --linux_perf_ipt_block -- ~/xpdfTest/build/xpdf/pdftotext ___FILE___ ~/xpdfTest/out/null
sudo ~/honggfuzz-2.5/honggfuzz -i ~/z3Test/inputs -o ~/z3Test/output-pt -n 1 --linux_perf_ipt_block -- ~/z3Test/z3-q -v:5 ___FILE___ 
sudo ~/honggfuzz-2.5/honggfuzz -i ~/tcpdumpTest/inputs -o ~/tcpdumpTest/output-pt -n 1 --linux_perf_ipt_block -- ~/tcpdumpTest/build/bin/tcpdump -vvvvXX -ee -nn -r ___FILE___
sudo ~/honggfuzz-2.5/honggfuzz -i ~/unrarTest/inputs -o ~/unrarTest/output-pt -n 1 --linux_perf_ipt_block -- ~/unrarTest/bin/unrar lpv ___FILE___

sudo ~/honggfuzz-2.5/honggfuzz -i ~/tcpdumpTest/inputs -o ~/tcpdumpTest/output-pt1 -n 1 --linux_perf_ipt_block -- ~/tcpdumpTest/build/bin/tcpdump -vvvvXX -ee -nn -r ___FILE___
sudo ~/honggfuzz-2.5/honggfuzz -i ~/xpdfTest/inputs -o ~/xpdfTest/output-pt1 -n 1 --linux_perf_ipt_block -- ~/xpdfTest/build/xpdf/pdftotext ___FILE___ ~/xpdfTest/out/null


# Ptfuzzer
cd ~/ptfuzzer/build/
sudo /home/nova/anaconda3/envs/py2/bin/python2.7 ./bin/ptfuzzer.py "-i ../../xpdfTest/inputs -o ../../xpdfTest/output-ptf" "../../xpdfTest/build/xpdf/pdftotext @@ ../../xpdfTest/out/null"





# nginx
# build with gcov
./configure --with-cc-opt=--coverage --with-ld-opt=-lgco
python coverage.py -f move -s ~/nginxTest/output-time/queue -d nginx/queue
python coverage.py -f move -s ~/nginxTest/output-afl/queue -d nginx-a/queue
python coverage.py -f move -s ~/nginxTest/output-pt -d nginx-pt/queue

cd ~/nginxTest/nginx-1.20.1/
~/afl-cov/afl-cov -d ~/coverage/nginx --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"cat AFL_FILE | LD_PRELOAD=~/nginxTest/preeny/x86_64-linux-gnu/desock.so ~/nginxTest/nginx-1.20.1/objs/nginx" \
--code-dir ~/nginxTest/nginx-1.20.1/objs/ --lcov-web-all --overwrite | tee ~/coverage/nginx/nginx.txt
~/afl-cov/afl-cov -d ~/coverage/nginx-a --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"cat AFL_FILE | LD_PRELOAD=~/nginxTest/preeny/x86_64-linux-gnu/desock.so ~/nginxTest/nginx-1.20.1/objs/nginx" \
--code-dir ~/nginxTest/nginx-1.20.1/objs/ --lcov-web-all --overwrite | tee ~/coverage/nginx-a/nginx-a.txt
~/afl-cov/afl-cov -d ~/coverage/nginx-pt --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"cat AFL_FILE | LD_PRELOAD=~/nginxTest/preeny/x86_64-linux-gnu/desock.so ~/nginxTest/nginx-1.20.1/objs/nginx" \
--code-dir ~/nginxTest/nginx-1.20.1/objs/ --lcov-web-all --overwrite | tee ~/coverage/nginx-pt/nginx-pt.txt


# lua
python coverage.py -f move -s ~/luaTest/output-time/queue -d lua/queue
cp -r ~/luaTest/workdir/queue lua-a/
python coverage.py -f move -s ~/luaTest/output-pt -d lua-pt/queue

~/afl-cov/afl-cov -d ~/coverage/lua/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"cat AFL_FILE | ~/luaTest/repo/lua" \
--code-dir ~/luaTest/repo/ --lcov-web-all --overwrite | tee ~/coverage/lua/lua.txt
~/afl-cov/afl-cov -d ~/coverage/lua-a --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"cat AFL_FILE | ~/luaTest/repo/lua" \
--code-dir ~/luaTest/repo/ --lcov-web-all --overwrite | tee ~/coverage/lua-a/lua-a.txt
~/afl-cov/afl-cov -d ~/coverage/lua-pt --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"cat AFL_FILE | ~/luaTest/repo/lua" \
--code-dir ~/luaTest/repo/ --lcov-web-all --overwrite | tee ~/coverage/lua-pt/lua-pt.txt

# gzip
# build with gcov
CFLAGS="-fprofile-arcs -ftest-coverage" ./configure
python coverage.py -f move -s ~/gzipTest/output-time/queue -d gzip/queue
python coverage.py -f move -s ~/gzipTest/output-afl/queue -d gzip-a/queue
python coverage.py -f move -s ~/gzipTest/output-pt -d gzip-pt/queue


cd ~/gzipTest/gzip-1.12/
~/afl-cov/afl-cov -d ~/coverage/gzip/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"/home/nova/gzipTest/gzip-1.12/gzip -c -k -d -v AFL_FILE" \
--code-dir ~/gzipTest/gzip-1.12/ --lcov-web-all --overwrite | tee ~/coverage/gzip/gzip.txt
~/afl-cov/afl-cov -d ~/coverage/gzip-a/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"/home/nova/gzipTest/gzip-1.12/gzip -c -k -d -v AFL_FILE" \
--code-dir ~/gzipTest/gzip-1.12/ --lcov-web-all --overwrite | tee ~/coverage/gzip-a/gzip-a.txt
~/afl-cov/afl-cov -d ~/coverage/gzip-pt/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"/home/nova/gzipTest/gzip-1.12/gzip -c -k -d -v AFL_FILE" \
--code-dir ~/gzipTest/gzip-1.12/ --lcov-web-all --overwrite | tee ~/coverage/gzip-pt/gzip-pt.txt


# readelf(on ProxFuzz3/4)
python coverage.py -f move -s ~/readelfTest/output-1day-time/queue -d readelf/queue
python coverage.py -f move -s ~/readelfTest/output-zafl/queue -d readelf-a/queue
python coverage.py -f move -s ~/readelfTest/output-pt -d readelf-pt/queue

~/afl-cov/afl-cov -d ~/coverage/readelf/ --coverage-cmd \
"/home/xjf/binutils-gdb/binutils/readelf AFL_FILE -a" \
--code-dir ~/binutils-gdb/binutils --lcov-web-all --overwrite | tee ~/coverage/readelf/readelf.txt
~/afl-cov/afl-cov -d ~/coverage/readelf-a/ --coverage-cmd \
"/home/xjf/binutils-gdb/binutils/readelf AFL_FILE -a" \
--code-dir ~/binutils-gdb/binutils --lcov-web-all --overwrite | tee ~/coverage/readelf-a/readelf-a.txt
~/afl-cov/afl-cov -d ~/coverage/readelf-pt/ --coverage-cmd \
"/home/xjf/binutils-gdb/binutils/readelf AFL_FILE -a" \
--code-dir ~/binutils-gdb/binutils --lcov-web-all --overwrite | tee ~/coverage/readelf-pt/readelf-pt.txt


# xpdf
# build with gcov(cmake file have been modified)
cmake ../xpdf-4.04/ -DENABLE_COVERAGE=1
make
# will appear to encounter errors with Qt, ignore them
python coverage.py -f move -s ~/xpdfTest/output-1day-time/queue -d xpdf/queue
python coverage.py -f move -s ~/xpdfTest/output-a-time/queue -d xpdf-a/queue
python coverage.py -f move -s ~/xpdfTest/output-pt -d xpdf-pt/queue


~/afl-cov/afl-cov -d ~/coverage/xpdf/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"/home/nova/xpdfTest/covbuild/xpdf/pdftotext AFL_FILE ~/xpdfTest/out/null" \
--code-dir ~/xpdfTest/covbuild/xpdf/CMakeFiles/pdftotext.dir --lcov-web-all --overwrite | tee ~/coverage/xpdf/xpdf.txt
~/afl-cov/afl-cov -d ~/coverage/xpdf-a/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"/home/xjf/xpdfTest/covbuild/xpdf/pdftotext AFL_FILE ~/xpdfTest/out/null" \
--code-dir ~/xpdfTest/covbuild/xpdf/CMakeFiles/pdftotext.dir --lcov-web-all --overwrite | tee ~/coverage/xpdf-a/xpdf-a.txt
~/afl-cov/afl-cov -d ~/coverage/xpdf-pt/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"/home/nova/xpdfTest/covbuild/xpdf/pdftotext AFL_FILE ~/xpdfTest/out/null" \
--code-dir ~/xpdfTest/covbuild/xpdf/CMakeFiles/pdftotext.dir --lcov-web-all --overwrite | tee ~/coverage/xpdf-pt/xpdf-pt.txt
~/afl-cov/afl-cov -d ~/coverage/xpdf-za/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"/home/nova/xpdfTest/covbuild/xpdf/pdftotext AFL_FILE ~/xpdfTest/out/null" \
--code-dir ~/xpdfTest/covbuild/xpdf/CMakeFiles/pdftotext.dir --lcov-web-all --overwrite | tee ~/coverage/xpdf-za/xpdf-za.txt



# z3
# build with gcov
CFLAGS="-fprofile-arcs -ftest-coverage" CXXFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="-lgcov --coverage" ./configure
python coverage.py -f move -s ~/z3Test/output-time/queue -d z3/queue
python coverage.py -f move -s ~/z3Test/output-a-time/queue -d z3-a/queue
python coverage.py -f move -s ~/z3Test/output-pt -d z3-pt/queue


~/afl-cov/afl-cov -d ~/coverage/z3/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"/home/xjf/z3/build/z3 -v:5 AFL_FILE" \
--code-dir ~/z3/build/ --lcov-web-all --overwrite| tee ~/coverage/z3/z3.txt
~/afl-cov/afl-cov -d ~/coverage/z3-a/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"/home/xjf/z3/build/z3 -v:5 AFL_FILE" \
--code-dir ~/z3/build/ --lcov-web-all --overwrite | tee ~/coverage/z3-a/z3-a.txt
~/afl-cov/afl-cov -d ~/coverage/z3-pt/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"/home/xjf/z3/build/z3 -v:5 AFL_FILE" \
--code-dir ~/z3/build/ --lcov-web-all --overwrite | tee ~/coverage/z3-pt/z3-pt.txt




# tcpdump
# build with gcov
sudo apt-get install libpcap-dev
CFLAGS="-fprofile-arcs -ftest-coverage" ./configure
python coverage.py -f move -s ~/tcpdumpTest/output-time/queue -d tcpdump/queue
python coverage.py -f move -s ~/tcpdumpTest/output-afl/queue -d tcpdump-a/queue
python coverage.py -f move -s ~/tcpdumpTest/output-pt -d tcpdump-pt/queue
python coverage.py -f move -s ~/tcpdumpTest/output-pt1 -d tcpdump-pt1/queue



~/afl-cov/afl-cov -d ~/coverage/tcpdump/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"/home/nova/tcpdumpTest/tcpdump-4.99.1/tcpdump -vvvvXX -ee -nn -r AFL_FILE" \
--code-dir ~/tcpdumpTest/tcpdump-4.99.1 --lcov-web-all --overwrite | tee ~/coverage/tcpdump/tcpdump.txt
~/afl-cov/afl-cov -d ~/coverage/tcpdump-a/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"/home/xjf/tcpdumpTest/tcpdump-4.99.1/tcpdump -vvvvXX -ee -nn -r AFL_FILE" \
--code-dir ~/tcpdumpTest/tcpdump-4.99.1 --lcov-web-all --overwrite | tee ~/coverage/tcpdump-a/tcpdump-a.txt
~/afl-cov/afl-cov -d ~/coverage/tcpdump-pt/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"/home/nova/tcpdumpTest/tcpdump-4.99.1/tcpdump -vvvvXX -ee -nn -r AFL_FILE" \
--code-dir ~/tcpdumpTest/tcpdump-4.99.1 --lcov-web-all --overwrite | tee ~/coverage/tcpdump-pt/tcpdump-pt.txt
~/afl-cov/afl-cov -d ~/coverage/tcpdump-pt1/ --disable-gcov-check DISABLE_GCOV_CHECK --coverage-cmd \
"/home/xjf/tcpdumpTest/tcpdump-4.99.1/tcpdump -vvvvXX -ee -nn -r AFL_FILE" \
--code-dir ~/tcpdumpTest/tcpdump-4.99.1 --lcov-web-all --overwrite | tee ~/coverage/tcpdump-pt1/tcpdump-pt1.txt

