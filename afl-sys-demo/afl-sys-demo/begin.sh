echo core >/proc/sys/kernel/core_pattern;
#./afl-fuzz -i ../gcctest/inputs/ -o ../gcctest/output/ ../gcctest/gcc-10.1.0/bin/toTest -o ../gcctest/output/null;
#./afl-fuzz -i ../gcctest/inputs/ -o ../gcctest/output/ -Q ../gcctest/gcc-10.1.0/bin/toTest -o ../gcctest/output/null;

./afl-fuzz -i ../gzipTest/inputs -o ../gzipTest/output -t 1000 ../gzipTest/toTest -c -k -d -v @@
./afl-fuzz -i ../gzipTest/inputs -o ../gzipTest/output -P ../gzipTest/gzip-1.12/aflbuild/gzip -t 1000 ../gzipTest/toTest -c -k -d @@
./afl-fuzz -i ../gzipTest/inputs -o ../gzipTest/output1 -t 1000 ../gzipTest/gzip-1.12/aflbuild/gzip -c -k -d @@
./afl-fuzz -i ../gzipTest/inputs -o ../gzipTest/output1 -n -t 1000 ../gzipTest/gzip-1.12/aflbuild/gzip -c -k -d @@

./afl-fuzz -i ../sqliteTest/aflQinputs -o ../sqliteTest/output1 ../sqliteTest/toTest -bail @@
afl-fuzz -i ../sqliteTest/aflQinputs -o ../sqliteTest/output ../sqliteTest/sqliteAFL/build/sqlite3 -bail @@

# # sqlite with coverage measurement
# afl-cov -d /root/xjf/sqliteTest/output1 --live --coverage-cmd \
# "cat AFL_FILE | /root/xjf/sqliteTest/sqliteCov/build/sqlite3 -bail" \
# --code-dir /root/xjf/sqliteTest/sqliteCov/build/

# ./afl-fuzz -i ../curlTest/inputs -o ../curlTest/output1 ../curlTest/toTest

./afl-fuzz -i ../xpdfTest/inputs -o ../xpdfTest/output ../xpdfTest/toTest @@ ../xpdfTest/out/null
# ./afl-fuzz -i ../xpdfTest/inputs/ -o ../xpdfTest/output1 ../xpdfTest/build/xpdf/pdftotext @@ ../xpdfTest/out/null 
# ./afl-fuzz -i ../xpdfTest/inputs/ -o ../xpdfTest/output2 -n ../xpdfTest/build/xpdf/pdftotext @@ ../xpdfTest/out/null 


# LD_PRELOAD="/root/xjf/nginxTest/preeny/x86_64-linux-gnu/desock.so" ./afl-fuzz -i ../nginxTest/inputs -o ../nginxTest/output1 -m 1000 ../nginxTest/toTest 

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
