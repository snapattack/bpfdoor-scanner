#!/usr/bin/env python3
import sys
import socket
import socketserver
import argparse
import ipaddress
import threading
import time
from queue import Queue

class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    pass

class ThreadedUDPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        if data == b'1':
            if self.client_address[0] not in compromised_hosts:
                print("[!] {} has been compromised".format(self.client_address[0]))
                compromised_hosts.append(self.client_address[0])

def banner():
    banner = '''

██████╗ ██████╗ ███████╗██████╗  ██████╗  ██████╗ ██████╗     
██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔══██╗    
██████╔╝██████╔╝█████╗  ██║  ██║██║   ██║██║   ██║██████╔╝    
██╔══██╗██╔═══╝ ██╔══╝  ██║  ██║██║   ██║██║   ██║██╔══██╗    
██████╔╝██║     ██║     ██████╔╝╚██████╔╝╚██████╔╝██║  ██║    
╚═════╝ ╚═╝     ╚═╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝    
                                                              
███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗   
██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗  
███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝  
╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗  
███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║  
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝  
                                                              
v1.0 - By the SnapAttack Research Team
'''
    print(banner)

def scan(target):
    print('[-] Scanning {}'.format(target))
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if verbose:
                with print_lock:
                    print('[-] Scanning {} port {}'.format(target, port))
            if s.connect_ex((target, port)) == 0:
                s.sendall(payload)

def threader():
    while True:
        target = q.get()
        scan(target)
        q.task_done()

if __name__ == "__main__":

    banner()

    ###########################################################################
    # Parse arguments
    ###########################################################################
    parser = argparse.ArgumentParser(usage='%(prog)s targets [options]')
    parser.add_argument(
        'targets', 
        type=str,
        help='IP address or range in CIDR notation to scan (e.g., 192.168.1.100 or 10.0.0.0/24)')

    parser.add_argument(
        '--target-ports',
        '-p',
        type=str,
        help='Comma separated list of ports to scan. Ranges are OK. (e.g, 22,80,443 or 1-1000)',
        default='21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080',
        required=False)

    parser.add_argument(
        '--ip',
        '-i',
        type=str,
        help='Your IP address',
        required=True)

    parser.add_argument(
        '--listen-port',
        '-l',
        type=int,
        help='Port to listen on from your IP address',
        required=True)

    parser.add_argument(
        '--verbose',
        '-v',
        default=False,
        action='store_true',
        help='Verbose mode - prints the current hosts and ports being scanned',
        required=False)

    try:
        args = parser.parse_args()
    except:
        parser.print_help()
        sys.exit(0)

    try:
        targets = []
        targets.append(str(ipaddress.IPv4Address(args.targets)))
    except ipaddress.AddressValueError:
        try:
            for addr in ipaddress.IPv4Network(args.targets):
                targets.append(str(addr))
        except ipaddress.NetmaskValueError:
            sys.exit('[!] Error: invalid target IP address or range')

    try:
        ports = []
        port_list = args.target_ports.split(',')
        for port in port_list:
            if '-' in port:
                port_range = port.split('-')
                if (int(port_range[0]) not in range(0,65536)):
                    raise Exception
                if (int(port_range[1]) not in range(0,65536)):
                    raise Exception
                for x in range(int(port_range[0]), int(port_range[1])+1):
                    if x not in ports:
                        ports.append(int(x))
            else:
                if (int(port) not in range(0,65536)):
                    raise Exception
                if int(port) not in ports:
                    ports.append(int(port))
    except:
        sys.exit('[!] Error: invalid target port list or range (--target-ports, -p)')

    try:
        listen_ip = str(ipaddress.IPv4Address(args.ip))
        if ipaddress.IPv4Address(listen_ip).is_loopback:
            sys.exit('[!] Error: you cannot listen on your loopback address')
        elif ipaddress.IPv4Address(listen_ip).is_private:
            print('[!] Warning: you are listening on a private IP address -- public IPs will not be able to reach back')
    except ipaddress.AddressValueError:
        sys.exit('[!] Error: invalid local IP address (--ip, -i')

    listen_port = args.listen_port
    if (listen_port not in range(0,65536)):
        sys.exit('[!] Error: invalid local port (--listen-port, -l')

    verbose = args.verbose or False

    compromised_hosts = []

    ###########################################################################
    # Construct the magic packet
    ###########################################################################
    # unsigned int    flag;   // 4 bytes
    # in_addr_t       ip;     // 4 bytes
    # unsigned short  port;   // 2 bytes
    # char   pass[14];        // 14 bytes

    # Assumes TCP with magic number 0x5293
    # If you want to modify for UDP or ICMP, the magic number is 0x7255
    payload = bytes.fromhex('52930000') + \
            socket.inet_aton(listen_ip) + \
            socket.htons(listen_port).to_bytes(2, 'little') + \
            bytes.fromhex('0000000000000000000000000000')

    ###########################################################################
    # Start the UDP Server
    ###########################################################################
    server = ThreadedUDPServer((listen_ip, listen_port), ThreadedUDPRequestHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True

    try:
        server_thread.start()
        print('[-] UDP server started at {} on port {}'.format(listen_ip, listen_port))
    except (KeyboardInterrupt, SystemExit):
        server.shutdown()
        server.server_close()
        sys.exit()

    ###########################################################################
    # Scan the targets
    ###########################################################################
    print('[-] Scanning {} ports on {} targets'.format(len(ports), len(targets)))
    print_lock = threading.Lock()

    q = Queue()

    # You may increase the number of threads at your own peril
    for x in range(4):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()
    
    for target in targets:
        q.put(target)
    
    # wait until the thread terminates
    q.join()

    print('[*] Scanning complete! Waiting 5 seconds for any remaining UDP messages to come back in...')
    time.sleep(5)

    if len(compromised_hosts) == 0:
        print('[*] Good news! None of the target hosts appear to be compromised!')
    else:
        print('[*] Uh oh! We found {} hosts that we believe to be compromised:'.format(len(compromised_hosts)))
        for host in compromised_hosts:
            print(host)
        print('')

    print('[*] Shutting down UDP server and exiting')
    server.shutdown()
    server.server_close()
    sys.exit()