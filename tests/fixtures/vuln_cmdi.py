import os
import subprocess

def ping_host(user_input):
    # VULN002: Command injection via os.system
    os.system("ping -c 1 " + user_input)

def run_command(user_input):
    # VULN002: Command injection via subprocess
    subprocess.call("ls " + user_input, shell=True)

def safe_command(host):
    subprocess.run(["ping", "-c", "1", host], check=True)
