from distutils.command.config import config
import numpy
from nearpy import Engine
from nearpy.hashes import RandomBinaryProjections
import os

from pytest import Item
from sqlalchemy import Unicode

# the configuration of LSH (default)
# note: the dim is also the maxinum number of the strings to be received at one time
# and the projection_count will be updated with the MAP_SIZE_POW2 of the AFL part
lsh_config = {"hash_name":"rbp", 
          "dim":640, 
          "projection_count":64}

# # the fifo used to transfer data or commands
# fifo_path1 = "/tmp/command_fifo"
# fifo_path2 = "/tmp/data_fifo"
log_path = "./logs/cur_log.txt"

def log_write(to_log):
    with open(log_path, "a+") as log_file:
        log_file.write(to_log + "\n")

# convert the received log strings to a float array that LSH can be applied
def get_toHash(items, raw_strings):
    toHash = numpy.zeros(lsh_config["dim"])
    item_count = 0
    # TODO: replace with some string-float mapping...
    for string in raw_strings:
        # if is string, use the original value
        try:
            param_value = int(string)
            toHash[item_count] = param_value
        except:
            toHash[item_count] = hash(string)
            
        item_count += 1
        if item_count >= lsh_config["dim"]:
            log_write("Items exceeded {}.".format(item_count))
            break
    
    return toHash

if __name__ == "__main__":
    # # set up pipes
    # os.mkfifo(fifo_path1)
    # os.mkfifo(fifo_path2)
    # command_fifo = open(fifo_path1, "rw+")
    # data_fifo = open(fifo_path2, "rw+")
    
    # use stdout and stdin as pipes:
    afl_map_size_pow = input()
    # get the projection_count as beginning 
    try:
        afl_map_size_pow = int(afl_map_size_pow)
        log_write("Get input: {}".format(afl_map_size_pow))
    except:
        log_write("Unable to get legal projection_count")
        exit(1)
    
    # check the range of projection_count 
    if afl_map_size_pow > 10 and afl_map_size_pow < 1024:
        # double the size of afl map size...
        lsh_config["projection_count"] = afl_map_size_pow*2
        log_write("Got.")
        print("Got.")
    else:
        log_write("projection_count {} not in a legal range.".format(afl_map_size_pow))
        exit(1)
        
    # set up LSH
    rbp = RandomBinaryProjections('rbp', lsh_config["projection_count"])
    rbp.reset(lsh_config["dim"])
    with open(log_path, "w+") as log_file:
        log_file.write("RBP built.\n")
    
    # Loop to get strings and send hash values in integer
    while(True):
        raw_strings = input().split(" ")
        # get the number of strings to be received
        items = len(raw_strings)
        if items < 0:
            # not a valid input
            log_write("Items is a negative number?")
            exit(2)
        if items == 0:
            # directly return
            print(0)
            continue
        toHash = get_toHash(items, raw_strings)
        # print(toHash)
        print(int(rbp.hash_vector(toHash)[0], 2))
    

