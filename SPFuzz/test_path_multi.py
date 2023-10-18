
import sys
import threading
import os
from tokenize import endpats
import signal
import sys
 
import time

count_upbound = 10000000
bitmap_size = 66000


# samples_paths = ["/data/zzx/benchmark/archieve/FFmpeg/compfuzzing/sys/raw_inputs/", 
#                  "/data/zzx/benchmark/archieve/FFmpeg/compfuzzing/dumb/raw_inputs/",
#                  "/data/zzx/benchmark/archieve/FFmpeg/compfuzzing/afl/raw_inputs/"]

# out_paths = ["/data/zzx/benchmark/archieve/FFmpeg/compfuzzing/logs/cur_tuple", 
#              "/data/zzx/benchmark/archieve/FFmpeg/compfuzzing/logs/cur_tuple1",
#              "/data/zzx/benchmark/archieve/FFmpeg/compfuzzing/logs/cur_tuple2"]

# # old_target_app = "/data/zzx/benchmark/archieve/FFmpeg/ffmpeg"
# # other_args = " -hide_banner -i @@ out.avi -y"
# cmd = "/data/zzx/benchmark/archieve/FFmpeg/ffmpeg -hide_banner -i @@ out.avi -y"

# record_paths = ["/data/zzx/benchmark/archieve/FFmpeg/compfuzzing/logs/afl-sys-paths.txt", 
#                 "/data/zzx/benchmark/archieve/FFmpeg/compfuzzing/logs/dumb-afl-paths.txt",
#                 "/data/zzx/benchmark/archieve/FFmpeg/compfuzzing/logs/input-paths.txt"]

def print_bitmap(map_to_print):
    for i in range(0, bitmap_size -1):
        print("{}: {}".format(i, map_to_print[i]))

def signal_handler(signal,frame):
    print('You pressed Ctrl + C!')
    sys.exit(0)
 
signal.signal(signal.SIGINT,signal_handler)


lock = threading.Lock()

total_path = 0
virgin_bitmap = []
temp_file = ''
cmd = ''
record_path = ''
sample_path = ''
    

def task(sample, taskId):
    global sample_path
    global temp_file
    # if not (sample.startswith("id") or sample.startswith("input")):
    #     continue

    
    tfile = f'{temp_file}_{taskId}'
    input = os.path.join(sample_path, sample)
    if not os.path.exists(input):
        return
    # use afl-showmap to get the bitmap of one exection
    os.system("afl-showmap -o {} -c -q -m none -t2000+ -- {}".format(tfile, cmd.replace('@@', input)))
            

def main():
    global total_path
    global virgin_bitmap

    i = 1
    global sample_path
    global temp_file 
    global record_path
    continue_loc = 0
    global cmd
    
    while i < len(sys.argv):
        if sys.argv[i] == '-h':
            print("""
            -h help
            -s sample folder
            -t tempfile location
            -o record path location
            -c continue from
            -- follow afl command
            """)
            return
        if sys.argv[i] == '-s':
            sample_path = sys.argv[i+1]
        if sys.argv[i] == '-t':
            temp_file = sys.argv[i+1]
        if sys.argv[i] == '-o':
            record_path = sys.argv[i+1]
        if sys.argv[i] == '-c':
            continue_loc = int(sys.argv[i+1])
        if sys.argv[i] == '--':
            cmd = ' '.join(sys.argv[i+1:])
            break
        i += 2

    # print("Ready to process: {}".format(samples_paths[args_option]))
    print('sample inputs:\t' + sample_path)
    print('temp file:\t' + temp_file)
    print('record file\t' + record_path)
    if continue_loc != 0:
        print(f'continue loc\t{continue_loc}')
    print('cmd:\t' + cmd)


    #initialize the bitmap
    for i in range(0, bitmap_size):
        virgin_bitmap.append(int(255))
    #initialize record file
    with open(record_path, "w"): pass

    samples = os.listdir(sample_path)
    samples.sort()
    
    GROUP_COUNT = 100
    # 1000 个一组
    temp_bitmap = []
    for i in range(0, bitmap_size):
        temp_bitmap.append(int(0))
        
    # min_count = int(samples[0][6:-1])
    # print("The min file count is {}({}).".format(samples[0] ,min_count))

    for i in range(continue_loc, min(count_upbound, len(samples)),GROUP_COUNT):
        print("Processing: {}, total_paths: {}".format(os.path.join(sample_path, samples[i]), total_path), end="\r")
        threads = []
        for j in range(i, i+GROUP_COUNT):
            t = threading.Thread(target=task, args=(samples[j], j-i))
            threads.append(t)
            t.start()
    
        for t in threads:
            t.join()

        
        for j in range(i, i+GROUP_COUNT):
            tfile = f'{temp_file}_{j-i}'

            for k in range(0, bitmap_size):
                temp_bitmap[k] = 0
            
            if not os.path.exists(tfile):
                continue
            with open(tfile, "r+") as f:
                for line in f:
                    # the last line is empty, skip it
                    if not line.startswith("0"):
                        continue
                    k = line.split(":")
                    temp_bitmap[ int( k[0] ) ] = int( k[1] )
                    
            has_new_bits = False
            # has new bits?
            for k in range(0, bitmap_size-1):
                if not has_new_bits:
                    if (temp_bitmap[k] & virgin_bitmap[k])!=0 :
                        has_new_bits = True
                virgin_bitmap[k] = virgin_bitmap[k] & (~temp_bitmap[k])
            
            if has_new_bits:
                total_path += 1
                with open(record_path, "a+") as record_f:
                    record_f.write("exec: {}, paths: {}\n".format(samples[j], total_path))
            else:
                # print("rm :{}".format(samples[j]))
                # os.system("rm -f {}".format(os.path.join(sample_path, samples[j])))
                pass
    
    return 


if __name__ == "__main__":
    main()
