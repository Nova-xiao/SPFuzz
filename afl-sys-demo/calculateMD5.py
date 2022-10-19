import os
import hashlib

file_path = "../xpdfTest/output/.cur_input"

def main():
    # file_path = input("File path is:")
    if not os.path.isfile(file_path):
        print("File not exists...")
        exit(1)
    md5_digest = hashlib.md5()
    with open(file_path, "r+") as f:
        for line in f:
            md5_digest.update(line.encode("utf-8"))
            
    print(md5_digest.hexdigest())
    

if __name__ == "__main__":
    main()