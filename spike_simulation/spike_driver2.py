#!/usr/bin/env python3
import sys
import pexpect
import logging
from tqdm import tqdm
import re
from io import StringIO, BytesIO
import os



def setup_logging(log_file):
    """Configure dual console+file logging"""
    logger = logging.getLogger('SPIKE_TRACER')
    logger.setLevel(logging.DEBUG)
    
    # File handler (full details)
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(file_formatter)
    
    # Console handler (brief output)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(message)s')
    ch.setFormatter(console_formatter)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

def run_spike(spike_path, elf_path, logger):
    cmd = [spike_path, "-d", "--log-commits", "--isa=RV32IMAFDC", elf_path]
    logger.debug(f"Starting SPIKE: {' '.join(cmd)}")
    outlog_r = BytesIO()

    # try:
    child = pexpect.spawn(' '.join(cmd))
    child.logfile_read = outlog_r

    while True:
        child.expect("spike")
        child.sendline("r 1")

        lines = str(outlog_r.getvalue(), encoding='utf-8').split(os.linesep)
        for line in lines:
            if re.fullmatch(r'core   0: 0x[0-9a-f]', line.strip()):
                print(f"===> {line}")
            else:
                print(f'---> {line}')
        
        input("")


        # proc.stderr.write("q\n")
        # for i in range(100):
        #     output = proc.stderr.readline()
        #     print("=====> ", output)
        # output = proc.stderr.readline()
        # print(proc.communicate(b'reg 0\n', timeout=1))
        # print("STOP")
        # proc.stdin.flush()
        
        # output = proc.stdout.readline()
        # logger.info([line.strip() for line in proc.stdout if line.strip()])

        # while True:
        #     output = process.stdout.readline()
            
        #     if output == '' and process.poll() is not None:
        #         break
        #     if output.lower() is not '(spike)':
        #         # Special handling for instruction traces
        #         if "core" in output:
        #             logger.info(output.strip())
        
        # return proc.poll()
    # except Exception as e:
    #     logger.error(f"SPIKE execution failed: {str(e)}")
    #     return 1

def main():
    if len(sys.argv) != 4:
        print("Usage: spike_driver.py <spike_path> <elf_path> <log_file>")
        sys.exit(1)
        
    spike_path = sys.argv[1]
    elf_path = sys.argv[2]
    log_file = sys.argv[3]
    
    logger = setup_logging(log_file)
    exit_code = run_spike(spike_path, elf_path, logger)
    
    logger.info(f"SPIKE completed with exit code: {exit_code}")
    sys.exit(exit_code)

if __name__ == "__main__":
    main()