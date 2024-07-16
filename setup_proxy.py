#!/usr/bin/env phtyon3

import os
import time

sysctl_conf = """#
# /etc/sysctl.conf - Configuration file for setting system variables
# See /etc/sysctl.d/ for additional system variables.
# See sysctl.conf (5) for information.
#

#kernel.domainname = example.com

# Uncomment the following to stop low-level messages on console
#kernel.printk = 3 4 1 3

###################################################################
# Functions previously found in netbase
#

# Uncomment the next two lines to enable Spoof protection (reverse-path filter)
# Turn on Source Address Verification in all interfaces to
# prevent some spoofing attacks
#net.ipv4.conf.default.rp_filter=1
#net.ipv4.conf.all.rp_filter=1

# Uncomment the next line to enable TCP/IP SYN cookies
# See http://lwn.net/Articles/277146/
# Note: This may impact IPv6 TCP sessions too
#net.ipv4.tcp_syncookies=1

# Uncomment the next line to enable packet forwarding for IPv4
net.ipv4.ip_forward=1

# Uncomment the next line to enable packet forwarding for IPv6
#  Enabling this option disables Stateless Address Autoconfiguration
#  based on Router Advertisements for this host
#net.ipv6.conf.all.forwarding=1


###################################################################
# Additional settings - these settings can improve the network
# security of the host and prevent against some network attacks
# including spoofing attacks and man in the middle attacks through
# redirection. Some network environments, however, require that these
# settings are disabled so review and enable them as needed.
#
# Do not accept ICMP redirects (prevent MITM attacks)
#net.ipv4.conf.all.accept_redirects = 0
#net.ipv6.conf.all.accept_redirects = 0
# _or_
"""

src_proxy = """#define COPYRIGHT "(c)3APA3A, Vladimir Dubrovin & 3proxy.org\\n"
                 "Documentation and sources: https://3proxy.org/\\n"
                 "Please read license agreement in \'copying\' file.\\n"
                 "You may not use this program without accepting license agreement"


#ifndef _3PROXY_H_
#define _3PROXY_H_
#include "version.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>


#define ANONYMOUS 1
#define MAXUSERNAME 128
#define _PASSWORD_LEN 256
#define MAXNSERVERS 5

#define UDPBUFSIZE 16384
#define TCPBUFSIZE 65536
#define SRVBUFSIZE (param->srv->bufsize?param->srv->bufsize:((param->service == S_UDPPM)?UDPBUFSIZE:TCPBUFSIZE))


#ifdef _WIN32
#include <winsock2.h>
#include <sys/timeb.h>
#ifndef _WINCE
#include <io.h>
#else
#include <sys/unistd.h>
#endif
#include <process.h>
#define SASIZETYPE int
#define SHUT_RDWR SD_BOTH
#else
#ifndef FD_SETSIZE
"""

rt_tables = """#
# reserved values
#
255     local
254     main
253     default
0       unspec
#
# local
#
#1      inr.ruhep

1 gw1
2 gw2
3 gw3
4 gw4
5 gw5
"""

startproxy = """#!/usr/bin/env phtyon3

import os
import subprocess
import re
import time

ip_route = subprocess.check_output(['ip','route'])
decoded = ip_route.decode('utf-8')
ip_strings = re.findall(r'192.168.\d{1,3}.\d{1,3} dev enx.+', decoded)
cfg_file_content = '''#! /usr/local/bin/3proxy
daemon
nserver 8.8.8.8
nscache 65536
timeouts 1 5 30 60 180 15 60
users root:CL:pass
#log /var/log/3proxy.log
#rotate 30
setgid 13
setuid 13
auth none
allow root
'''

gateway_info = []
if len(ip_strings) > 0:
    for s in ip_strings:
        splited = s.split(' ')
        ip = splited[0]
        dev = splited[2]
        gateway_info.append([dev, ip])

    gateway_info.sort()

    port_no = 3128
    for g in gateway_info:
        mid_no = g[1].split('.')[2]
        pr = f'proxy -p{port_no} -e192.168.{mid_no}.100\\n'
        cfg_file_content += pr
        port_no += 1
    cfg_file_content += 'flush'

    home_path = '/home/' + os.getlogin()
    cfg_file = home_path + '/3proxy.cfg'
    with open(cfg_file, 'w') as f:
        f.write(cfg_file_content)
    
    os.chdir(home_path + '/3proxy')
    os.system("sudo make install")
    time.sleep(5)
    os.chdir(home_path)

    num = 1
    for p in gateway_info:
        print('---------------------------------------')
        print(f'Proxy No. {num} : setting up IP')
        dev_id = p[0]
        ip_nums = p[1].split('.')
        mid_no = ip_nums[2]
        g_no = ip_nums[3]
        cmd1 = f'sudo ifconfig {dev_id} 192.168.{mid_no}.100'
        cmd2 = f'sudo ip route add 192.168.{mid_no}.0/24 dev {dev_id} src 192.168.{mid_no}.100 table gw{num}'
        cmd3 = f'sudo ip route add default via 192.168.{mid_no}.{g_no} dev {dev_id} table gw{num}'
        cmd4 = f'sudo ip rule add from 192.168.{mid_no}.100/32 table gw{num}'
        cmd5 = f'sudo ip rule add to 192.168.{mid_no}.100/32 table gw{num}'
        os.system(cmd1)
        time.sleep(2)
        print(f'Proxy No. {num} : setting up routes')
        os.system(cmd2)
        os.system(cmd3)
        os.system(cmd4)
        os.system(cmd5)
        time.sleep(3)
        num += 1
    print('---------------------------------------')
    print('Start the proxy')
    start_proxy_cmd = f'sudo 3proxy {cfg_file}'
    os.system(start_proxy_cmd)
"""
home_path = '/home/' + os.getlogin()
os.chdir(home_path)
print(os.getcwd())

with open("/etc/sysctl.conf", "w") as f:
    f.write(sysctl_conf)

os.system('sudo apt -y install fail2ban software-properties-common build-essential libevent-dev libssl-dev git')
time.sleep(10)
os.system('git clone https://github.com/3proxy/3proxy.git')
time.sleep(2)
os.chdir(home_path + '/3proxy')

with open("src/proxy.h", "w") as f:
    f.write(src_proxy)

os.system('sudo ln -s Makefile.Linux Makefile')
os.system('sudo make')
time.sleep(8)
os.system('sudo make install')
time.sleep(5)
os.system('sudo systemctl is-enabled 3proxy.service')

with open("/etc/iproute2/rt_tables", "w") as f:
    f.write(rt_tables)

os.chdir(home_path)
with open("startproxy.py", "w") as f:
    f.write(startproxy)

os.system('sudo python3 startproxy.py')