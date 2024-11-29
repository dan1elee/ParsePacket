import ipaddress
import argparse
import glob
import os
import multiprocessing
import shutil


def key_f(src_ip: str, dst_ip: str, version: int) -> int:
        if version == 4:
            s_ip = int(ipaddress.IPv4Address(src_ip))
            d_ip = int(ipaddress.IPv4Address(dst_ip))
            if s_ip < d_ip:
                return (s_ip << 32) | d_ip
            else:
                return (d_ip << 32) | s_ip
        else:
            s_ip = int(ipaddress.IPv6Address(src_ip))
            d_ip = int(ipaddress.IPv6Address(dst_ip))
            if s_ip < d_ip:
                return (s_ip << 128) | d_ip
            else:
                return (d_ip << 128) | s_ip
def key_to_str(key: int)->str:
    return f"{key & ((1 << 32) - 1)}, {key >> 32}"

def pairs_gen(in_path: str):
    f = open(in_path, "r")
    
    ip_pool = set()
    f.readline()
    line = f.readline()
    line_num = 0
    while line:
        line_num += 1
        if line_num % 10000 == 0:
            print(f"Parsed {line_num} lines")
        line = line.strip()
        sp = line.split(',')
        ip_v = sp[8]
        if ip_v == "4":
            k = key_f(sp[24], sp[25], 4)
            ip_pool.add(k)
        elif ip_v == "6":
            k = key_f(sp[31], sp[32], 6)
            ip_pool.add(k)
        line = f.readline()
    f.close()

    out_path = os.path.join(IN_DIR, "pairs", f"{os.path.basename(in_path)}.pairs")
    f_out = open(out_path, "w")
    for idx, pair in enumerate(ip_pool):
        if idx % 10000 == 0:
            print(f"Parsed {idx} pairs")
        f_out.write(key_to_str(pair))
        f_out.write("\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--in_file")
    parser.add_argument("--out_file")
    args = parser.parse_args()

    IN_PATH = args.in_file
    OUT_PATH = args.out_file
    IN_DIR = os.path.dirname(IN_PATH)

    PAIRS_PATH = os.path.join(IN_DIR, "pairs")
    if os.path.isdir(PAIRS_PATH):
        shutil.rmtree(PAIRS_PATH)
    os.mkdir(PAIRS_PATH)

    in_files = glob.glob(IN_PATH)
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        pool.map(pairs_gen, in_files)