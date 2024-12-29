# To profile the actual optimization effects of the forkserver
# and the execution speed with syscall-coverage feedback

# nginx
LD_PRELOAD=~/nginxTest/preeny/x86_64-linux-gnu/desock.so ./afl-fuzz -i ~/nginxTest/inputs2 -o ~/nginxTest/output- -m 1000 -n ~/nginxTest/build/sbin/nginx
LD_PRELOAD=~/nginxTest/preeny/x86_64-linux-gnu/desock.so ./afl-fuzz -i ~/nginxTest/inputs2 -o ~/nginxTest/output- -m 1000 ~/nginxTest/aflbuild/sbin/nginx
LD_PRELOAD=~/nginxTest/preeny/x86_64-linux-gnu/desock.so ./afl-fuzz -i ~/nginxTest/inputs2 -o ~/nginxTest/output- -m 1000 -n ~/nginxTest/aflbuild/sbin/nginx
LD_PRELOAD=~/nginxTest/preeny/x86_64-linux-gnu/desock.so ./afl-fuzz -i ~/nginxTest/inputs2 -o ~/nginxTest/output- -m 1000 ~/nginxTest/toTest 

# lua
./afl-fuzz -m 1000 -n -i /home/xjf/luaTest/corpus/selected -o /home/xjf/luaTest/workdir- -- /home/xjf/luaTest/out/toTest
./afl-fuzz -m 1000 -i /home/xjf/luaTest/corpus/selected -o /home/xjf/luaTest/workdir- -- /home/xjf/luaTest/out/lua.afl
./afl-fuzz -m 1000 -n -i /home/xjf/luaTest/corpus/selected -o /home/xjf/luaTest/workdir- -- /home/xjf/luaTest/out/lua.afl

./afl-fuzz -m 1000 -i /home/xjf/luaTest/corpus/selected -o /home/xjf/luaTest/workdir- -- /home/xjf/luaTest/out/toTest


# z3
./afl-fuzz -n -i ~/z3Test/inputs -o ~/z3Test/output- -- ~/z3Test/toTest -v:5 @@

./afl-fuzz -i ~/z3Test/inputs -o ~/z3Test/output- -- ~/z3Test/toTest -v:5 @@



# gifsicle
./afl-fuzz -i /home/xjf/gifsicleTest/inputs -o /home/xjf/gifsicleTest/output- -- /home/xjf/gifsicleTest/gifsicle.afl @@ #0 -o /home/xjf/gifsicleTest/newa.gif
./afl-fuzz -n -i /home/xjf/gifsicleTest/inputs -o /home/xjf/gifsicleTest/output- -- /home/xjf/gifsicleTest/gifsicle.afl @@ #0 -o /home/xjf/gifsicleTest/newa.gif
./afl-fuzz -i /home/xjf/gifsicleTest/inputs -o /home/xjf/gifsicleTest/output- -- /home/xjf/gifsicleTest/toTest @@ #0 -o /home/xjf/gifsicleTest/newa.gif
./afl-fuzz -n -i /home/xjf/gifsicleTest/inputs -o /home/xjf/gifsicleTest/output- -- /home/xjf/gifsicleTest/toTest @@ #0 -o /home/xjf/gifsicleTest/newa.gif


# tcpdump
./afl-fuzz -m none -i ~/tcpdumpTest/inputs2 -o ~/tcpdumpTest/output- -- ~/tcpdumpTest/build/toTest -vvvvXX -ee -nn -r @@
./afl-fuzz -m none -i ~/tcpdumpTest/inputs2 -o ~/tcpdumpTest/output- -- ~/tcpdumpTest/aflbuild/bin/tcpdump -vvvvXX -ee -nn -r @@
./afl-fuzz -n -m none -i ~/tcpdumpTest/inputs2 -o ~/tcpdumpTest/output- -- ~/tcpdumpTest/build/toTest -vvvvXX -ee -nn -r @@
./afl-fuzz -n -m none -i ~/tcpdumpTest/inputs2 -o ~/tcpdumpTest/output- -- ~/tcpdumpTest/aflbuild/bin/tcpdump -vvvvXX -ee -nn -r @@


# perlbench
./afl-fuzz -t 1000 -m none -i ~/specTest/inputs/perlbench -o ~/specTest/output/perlbench- -- ~/specTest/bin/perlbench/toTest @@ 
./afl-fuzz -t 1000 -m none -i ~/specTest/inputs/perlbench -o ~/specTest/output/perlbench- -- ~/specTest/bin/perlbench/perlbench_r.afl @@ 
./afl-fuzz -n -t 1000 -m none -i ~/specTest/inputs/perlbench -o ~/specTest/output/perlbench- -- ~/specTest/bin/perlbench/toTest @@ 
./afl-fuzz -n -t 1000 -m none -i ~/specTest/inputs/perlbench -o ~/specTest/output/perlbench- -- ~/specTest/bin/perlbench/perlbench_r.afl @@ 

# omnetpp
./afl-fuzz -t 2000+ -m 5000 -i ~/specTest/inputs/omnetpp -o ~/specTest/output/omnetpp- -- ~/specTest/bin/omnetpp/toTest @@ 
./afl-fuzz -t 2000+ -m 5000 -i ~/specTest/inputs/omnetpp -o ~/specTest/output/omnetpp- -- ~/specTest/bin/omnetpp/omnetpp_r.afl @@ 
./afl-fuzz -n -t 2000+ -m 5000 -i ~/specTest/inputs/omnetpp -o ~/specTest/output/omnetpp- -- ~/specTest/bin/omnetpp/toTest @@ 
./afl-fuzz -n -t 2000+ -m 5000 -i ~/specTest/inputs/omnetpp -o ~/specTest/output/omnetpp- -- ~/specTest/bin/omnetpp/omnetpp_r.afl @@ 


# xalancbmk
./afl-fuzz -t 2000+ -m 5000 -i ~/specTest/inputs/xalancbmk -o ~/specTest/output/xalancbmk- -- ~/specTest/bin/xalancbmk/toTest @@ ~/specTest/xalanc.xsl
./afl-fuzz -t 2000+ -m 5000 -i ~/specTest/inputs/xalancbmk -o ~/specTest/output/xalancbmk- -- ~/specTest/bin/xalancbmk/cpuxalan_r.afl @@ ~/specTest/xalanc.xsl
./afl-fuzz -n -t 2000+ -m 5000 -i ~/specTest/inputs/xalancbmk -o ~/specTest/output/xalancbmk- -- ~/specTest/bin/xalancbmk/toTest @@ ~/specTest/xalanc.xsl
./afl-fuzz -n -t 2000+ -m 5000 -i ~/specTest/inputs/xalancbmk -o ~/specTest/output/xalancbmk- -- ~/specTest/bin/xalancbmk/cpuxalan_r.afl @@ ~/specTest/xalanc.xsl

# gzip
./afl-fuzz -i ../gzipTest/inputs -o ../gzipTest/output- -t 1000 ../gzipTest/toTest -c -k -d -v @@
./afl-fuzz -i ../gzipTest/inputs -o ../gzipTest/output- -t 1000 ../gzipTest/gzip-1.12/aflbuild/gzip -c -k -d @@
./afl-fuzz -n -i ../gzipTest/inputs -o ../gzipTest/output- -t 1000 ../gzipTest/toTest -c -k -d -v @@
./afl-fuzz -n -i ../gzipTest/inputs -o ../gzipTest/output- -t 1000 ../gzipTest/gzip-1.12/aflbuild/gzip -c -k -d @@

# readelf
./afl-fuzz -i ~/readelfTest/small-inputs -o ~/readelfTest/output- -- ~/readelfTest/build/toTest -a @@
./afl-fuzz -i ~/readelfTest/small-inputs -o ~/readelfTest/output -- ~/readelfTest/build/readelf.zafl -a @@
./afl-fuzz -n -i ~/readelfTest/small-inputs -o ~/readelfTest/output- -- ~/readelfTest/build/toTest -a @@
./afl-fuzz -n -i ~/readelfTest/small-inputs -o ~/readelfTest/output -- ~/readelfTest/build/readelf.zafl -a @@


# xpdf
./afl-fuzz -m 5000 -i ~/xpdfTest/inputs -o ~/xpdfTest/output- -- ~/xpdfTest/toTest @@ ~/xpdfTest/out/null
./afl-fuzz -m 5000 -i ~/xpdfTest/inputs -o ~/xpdfTest/output- -- ~/xpdfTest/pdftotext.zafl @@ ~/xpdfTest/out/null
./afl-fuzz -n -m 5000 -i ~/xpdfTest/inputs -o ~/xpdfTest/output- -- ~/xpdfTest/toTest @@ ~/xpdfTest/out/null
./afl-fuzz -n -m 5000 -i ~/xpdfTest/inputs -o ~/xpdfTest/output- -- ~/xpdfTest/pdftotext.zafl @@ ~/xpdfTest/out/null

# imgdataopt
./afl-fuzz -i ~/imgdataoptTest/inputs -o ~/imgdataoptTest/output- -- ~/imgdataoptTest/imgdataopt-afl/imgdataopt @@ /home/xjf/imgdataoptTest/imgdataopt/null
./afl-fuzz -i ~/imgdataoptTest/inputs -o ~/imgdataoptTest/output- -- ~/imgdataoptTest/imgdataopt/toTest @@ /home/xjf/imgdataoptTest/imgdataopt/null
./afl-fuzz -n -i ~/imgdataoptTest/inputs -o ~/imgdataoptTest/output- -- ~/imgdataoptTest/imgdataopt-afl/imgdataopt @@ /home/xjf/imgdataoptTest/imgdataopt/null
./afl-fuzz -n -i ~/imgdataoptTest/inputs -o ~/imgdataoptTest/output- -- ~/imgdataoptTest/imgdataopt/imgdataopt @@ /home/xjf/imgdataoptTest/imgdataopt/null

# yara
./afl-fuzz -i ~/yaraTest/rule-inputs -o ~/yaraTest/output- -x ~/yaraTest/rules_fuzzer.dict -- /home/xjf/yaraTest/yara-4.4.0/aflbuild/.libs/yarac @@ /home/xjf/yaraTest/oss-fuzz/dotnet_fuzzer_corpus/obfuscated
./afl-fuzz -i ~/yaraTest/rule-inputs -o ~/yaraTest/output- -x ~/yaraTest/rules_fuzzer.dict -- /home/xjf/yaraTest/toTest @@ /home/xjf/yaraTest/oss-fuzz/dotnet_fuzzer_corpus/obfuscated
./afl-fuzz -n -i ~/yaraTest/rule-inputs -o ~/yaraTest/output- -x ~/yaraTest/rules_fuzzer.dict -- /home/xjf/yaraTest/yara-4.4.0/aflbuild/yarac @@ /home/xjf/yaraTest/oss-fuzz/dotnet_fuzzer_corpus/obfuscated
./afl-fuzz -n -i ~/yaraTest/rule-inputs -o ~/yaraTest/output- -x ~/yaraTest/rules_fuzzer.dict -- /home/xjf/yaraTest/toTest @@ /home/xjf/yaraTest/oss-fuzz/dotnet_fuzzer_corpus/obfuscated

# mcf
./afl-fuzz -t 2000+ -m 5000 -i ~/specTest/inputs/mcf -o ~/specTest/output/mcf- -- ~/specTest/bin/mcf/toTest @@ 
./afl-fuzz -t 2000+ -m 5000 -i ~/specTest/inputs/mcf -o ~/specTest/output/mcf- -- ~/specTest/bin/mcf/mcf_r.afl @@ 
./afl-fuzz -n -t 2000+ -m 5000 -i ~/specTest/inputs/mcf -o ~/specTest/output/mcf- -- ~/specTest/bin/mcf/mcf_r @@ 
./afl-fuzz -n -t 2000+ -m 5000 -i ~/specTest/inputs/mcf -o ~/specTest/output/mcf- -- ~/specTest/bin/mcf/mcf_r.afl @@ 

# xalancbmk
./afl-fuzz -t 2000+ -m 5000 -i ~/specTest/inputs/xalancbmk -o ~/specTest/output/xalancbmk- -- ~/specTest/bin/xalancbmk/toTest @@ ~/specTest/xalanc.xsl
./afl-fuzz -t 2000+ -m 5000 -i ~/specTest/inputs/xalancbmk -o ~/specTest/output/xalancbmk- -- ~/specTest/bin/xalancbmk/cpuxalan_r.afl @@ ~/specTest/xalanc.xsl
./afl-fuzz -n -t 2000+ -m 5000 -i ~/specTest/inputs/xalancbmk -o ~/specTest/output/xalancbmk- -- ~/specTest/bin/xalancbmk/toTest @@ ~/specTest/xalanc.xsl
./afl-fuzz -n -t 2000+ -m 5000 -i ~/specTest/inputs/xalancbmk -o ~/specTest/output/xalancbmk- -- ~/specTest/bin/xalancbmk/cpuxalan_r.afl @@ ~/specTest/xalanc.xsl

# x264
./afl-fuzz -t 2000+ -m 5000 -i ~/specTest/inputs/x264 -o ~/specTest/output/x264- -- ~/specTest/bin/x264/toTest --pass 1 --bitrate 1000 --frames 1000 -o ~/specTest/out.flv @@ 1280x720
./afl-fuzz -t 2000+ -m 5000 -i ~/specTest/inputs/x264 -o ~/specTest/output/x264- -- ~/specTest/bin/x264/x264_r.afl --pass 1 --bitrate 1000 --frames 1000 -o ~/specTest/out1.flv @@ 1280x720
./afl-fuzz -n -t 2000+ -m 5000 -i ~/specTest/inputs/x264 -o ~/specTest/output/x264- -- ~/specTest/bin/x264/toTest --pass 1 --bitrate 1000 --frames 1000 -o ~/specTest/out.flv @@ 1280x720
./afl-fuzz -n -t 2000+ -m 5000 -i ~/specTest/inputs/x264 -o ~/specTest/output/x264- -- ~/specTest/bin/x264/x264_r.afl --pass 1 --bitrate 1000 --frames 1000 -o ~/specTest/out1.flv @@ 1280x720

# deepsjeng
./afl-fuzz -t 5000 -m 5000 -i ~/specTest/inputs/deepsjeng -o ~/specTest/output/deepsjeng- -x ~/specTest/deepsjeng.dic -- ~/specTest/bin/deepsjeng/toTest @@ 
./afl-fuzz -t 5000+ -m 5000 -i ~/specTest/inputs/deepsjeng -o ~/specTest/output/deepsjeng- -x ~/specTest/deepsjeng.dic -- ~/specTest/bin/deepsjeng/deepsjeng_r.afl @@ 
./afl-fuzz -n -t 5000 -m 5000 -i ~/specTest/inputs/deepsjeng -o ~/specTest/output/deepsjeng- -x ~/specTest/deepsjeng.dic -- ~/specTest/bin/deepsjeng/deepsjeng_r @@ 
./afl-fuzz -n -t 5000+ -m 5000 -i ~/specTest/inputs/deepsjeng -o ~/specTest/output/deepsjeng- -x ~/specTest/deepsjeng.dic -- ~/specTest/bin/deepsjeng/deepsjeng_r.afl @@ 


# bsdtar
./afl-fuzz -i ~/bsdtarTest/inputs -o ~/bsdtarTest/output- -- /home/xjf/anaconda3/bin/toTest -a -cf archive.tar @@
./afl-fuzz -i ~/bsdtarTest/inputs -o ~/bsdtarTest/output- -n -- /home/xjf/anaconda3/bin/toTest -a -cf archive.tar @@
AFL_SKIP_BIN_CHECK=1 ./afl-fuzz -i ~/bsdtarTest/inputs -o ~/bsdtarTest/output- -D -- /home/xjf/anaconda3/bin/toTest -a -cf archive.tar @@



# certbasic
AFL_SKIP_BIN_CHECK=1 ./afl-fuzz -i ~/certbasicTest/inputs -o ~/certbasicTest/output- -n -- ~/certbasicTest/bin/toTest @@
./afl-fuzz -i /home/xjf/certbasicTest/inputs -o /home/xjf/certbasicTest/output- -n -- /home/xjf/certbasicTest/bin/cert-basic.zafl @@
AFL_SKIP_BIN_CHECK=1 ./afl-fuzz -i ~/certbasicTest/inputs -o ~/certbasicTest/output- -- ~/certbasicTest/bin/toTest @@


