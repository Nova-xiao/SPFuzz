import os
import sys

count_upbound = 1000000

# samples_path = "/home/xjf/xpdfTest/output/queue/"
samples_path = "/data/xjf/cur_inputs/"
out_path = "/home/xjf/afl-sys-demo/logs/cur_tuple"
old_target_app = "/home/xjf/xpdfTest/build/xpdf/pdftotext"
new_target_app = "/home/xjf/xpdfTest/toTest"
other_args = "/home/xjf/xpdfTest/out/null"

old_record_path = "/home/xjf/afl-sys-demo/logs/oldTuples.txt"
new_record_path = "/home/xjf/afl-sys-demo/logs/newTuples.txt"
total_bitmap = []

def read_old_tuples(sample_path, id):
    # use afl-showmap to get the bitmap of one exection
    os.system("afl-showmap -o {} -c -e {} {} {}".format(out_path, old_target_app, sample_path, other_args))
    with open(out_path, "r+") as f:
        for line in f:
            # the last line is empty, skip it
            if not line.startswith("0"):
                continue
            total_bitmap[ int( (line.split(":"))[0] ) ] = True
            
    # add up bitmap at this time
    tuple_number = 0
    for i in range(0, 66000):
        if(total_bitmap[i]):
            tuple_number += 1

    # and record it 
    with open(old_record_path, "a+") as f:
        f.write("Until id {}: {} ({})\n".format(id, tuple_number, sample_path))



def read_new_tuples(sample_path, id):
    # use afl-showmap to get the bitmap of one exection
    os.system("./afl-sys-showmap -o {} -c -e {} {} {}".format(out_path, new_target_app, sample_path, other_args))
    with open(out_path, "r+") as f:
        for line in f:
            # the last line is empty, skip it
            if not line.startswith("0"):
                continue
            total_bitmap[ int( (line.split(":"))[0] ) ] = True
            
    # add up bitmap at this time
    tuple_number = 0
    for i in range(0, 66000):
        if(total_bitmap[i]):
            tuple_number += 1

    # and record it 
    with open(new_record_path, "a+") as f:
        f.write("Until id {}: {} ({})\n".format(id, tuple_number, sample_path))


def main():
    read_tuples = None
    # identify read new tuples or not
    read_new_or_not = input("Please confirm whether to read new tuples or not(y or n):")
    if read_new_or_not=="y":
        read_tuples = read_new_tuples
        with open(new_record_path, "w"): pass
    elif read_new_or_not=="n":
        read_tuples = read_old_tuples
        with open(old_record_path, "w"): pass
    else:
        print("Option not supported.")
        return

    #initialize the bitmap
    for i in range(0, 66000):
        total_bitmap.append(False)

    samples = os.listdir(samples_path)
    samples.sort()

    count = 0
    for sample in samples:
        if not (sample.startswith("id") or sample.startswith("input")):
            continue
        read_tuples(os.path.join(samples_path, sample), count)
        count += 1
        if count >= count_upbound:
            break

if __name__ == "__main__":
    main()

