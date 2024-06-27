#!/usr/bin/env phtyon3

import os
import subprocess
import re
import time

ip_route = subprocess.check_output(['ip','route'])
decoded = ip_route.decode('utf-8')
ip_strings = re.findall(r'192.168.\d{1,3}.\d{1,3} dev enx.+', decoded)
# cfg_file_content = '#! /usr/local/bin/3proxy\ndaemon\nnserver 8.8.8.8\nnscache 65536\ntimeouts 1 5 30 60 180 15 60\nusers root:CL:pass\n#log /var/log/3proxy.log\n#rotate 30\nsetgid 13\nsetuid 13\nauth none\nallow root\n'
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