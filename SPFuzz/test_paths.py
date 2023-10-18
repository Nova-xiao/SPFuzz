from ast import arg
import sys
import os
from tokenize import endpats

count_upbound = 10000000
bitmap_size = 66000

samples_paths = ["/home/xjf/relationTest/afl-sys-inputs/", 
                 "/data/xjf/relationTest-gzip/dumb-afl-inputs/",
                 "/home/xjf/gzipTest/inputs/"]
out_paths = ["/home/xjf/afl-sys-demo/logs/cur_tuple", 
             "/home/xjf/afl-sys-demo/logs/cur_tuple1",
             "/home/xjf/afl-sys-demo/logs/cur_tuple2"]
old_target_app = "/home/xjf/readelfTest/build/readelf.zafl"
other_args = " -c -d -k "

record_paths = ["/home/xjf/relationTest/sys-paths0.txt", 
                "/data/xjf/relationTest-gzip/dumb-afl-paths.txt",
                "/data/xjf/relationTest-gzip/input-paths.txt"]

def print_bitmap(map_to_print):
    for i in range(0, bitmap_size -1):
        print("{}: {}".format(i, map_to_print[i]))

def read_tuples(sample_path, virgin_bitmap, total_path, args_option):
    temp_bitmap = []
    for i in range(0, bitmap_size):
        temp_bitmap.append(int(0))
    # use afl-showmap to get the bitmap of one exection
    os.system("afl-showmap -o {} -c -q {} {} {}".format(out_paths[args_option], old_target_app, other_args, sample_path))
    tuples_count = 0
    with open(out_paths[args_option], "r+") as f:
        for line in f:
            # the last line is empty, skip it
            if not line.startswith("0"):
                continue
            temp_bitmap[ int( (line.split(":"))[0] ) ] = int( (line.split(":"))[1] )
            tuples_count += 1
            
    has_new_bits = False
    # has new bits?
    for i in range(0, bitmap_size-1):
        if not has_new_bits:
            if (temp_bitmap[i] & virgin_bitmap[i])!=0 :
                has_new_bits = True
        virgin_bitmap[i] = virgin_bitmap[i] & (~temp_bitmap[i])
    
    if has_new_bits:
        total_path += 1
        
    return total_path, has_new_bits
            

def main():
    total_path = 0
    virgin_bitmap = []
    
    args_option = int(input("Please input args set number:"))
    print("Ready to process: {}".format(samples_paths[args_option]))
    
    #initialize the bitmap
    for i in range(0, bitmap_size):
        virgin_bitmap.append(int(255))
    #initialize record file
    with open(record_paths[args_option], "w"): pass

    samples = os.listdir(samples_paths[args_option])
    samples.sort()

    count = 0
    for sample in samples:
        # if not (sample.startswith("id") or sample.startswith("input")):
        #     continue
        print("Processing: {}, total_paths: {}".format(sample, total_path), end="\r")
        total_path, has_new_bits = read_tuples(os.path.join(samples_paths[args_option], sample), virgin_bitmap, total_path, args_option)
        if has_new_bits:
            with open(record_paths[args_option], "a+") as record_f:
                record_f.write("exec: {}, paths: {}\n".format(count, total_path))
        count += 1
        if count >= count_upbound:
                break
    
    return 

if __name__ == "__main__":
    main()
