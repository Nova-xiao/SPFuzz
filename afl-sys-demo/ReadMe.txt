1. 首先安装NoDrop，进入NoDrop/build使用CMake进行安装：
    cmake ..
    make load
    （重新安装时可先删除build中内容） 
2. 在afl-sys-demo中使用make可编译，如开启debug模式（可在logs/logging.txt中查看日志），
    可使用make debug=1

3. AFL-SYS的dump模式：首先修改forkserver.h中名为 CUR_INPUT_DUMP_PATH 的宏来指定导出变异出的文件的路径，然后在执行时加入选项-P XXXX(XXXX目前指定一个随意的路径即可)。
注意：太多的文件会占用较大的空间，记得及时停掉

4. 对AFL的修改：
增加的两个宏INFO_DUMP_FILE和FILE_DUMP_PATH分别是记录path变化的文件保存路径 和 每次变异出的文件的保存路径。
保存变异文件的部分被注释掉了，搜索第二个宏可以找到对应部分。
