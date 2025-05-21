#!/usr/bin/env python3
import sys
import subprocess
import logging
from datetime import datetime

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
    cmd = [spike_path, "-d", "--log-commits", elf_path]
    logger.debug(f"Starting SPIKE: {' '.join(cmd)}")
    
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,    # Enables writing commands
            stdout=subprocess.PIPE,   # Enables reading output
            text=True,                # Work with strings (not bytes)
            bufsize=10                # Line buffering
        )
        # while True:
        # logger.info(output)
        print("START")
        proc.stdin.write("reg 0\n")
        # output = proc.stdout.readline()
        # output = proc.stderr.readline()
        # print("=====> ", output)
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
        
        return proc.poll()
    except Exception as e:
        logger.error(f"SPIKE execution failed: {str(e)}")
        return 1

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