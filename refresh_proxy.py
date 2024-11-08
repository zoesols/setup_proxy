#!/usr/bin/env phtyon3

import os
import subprocess
import re
import time

ip_route = subprocess.check_output(['ip','route'])
decoded = ip_route.decode('utf-8')
ip_strings = re.findall(r'192.168.\d{1,3}.\d{1,3} dev enx.+', decoded)


gateway_info = []
if len(ip_strings) > 0:
    for s in ip_strings:
        splited = s.split(' ')
        ip = splited[0]
        dev = splited[2]
        gateway_info.append([dev, ip])

    gateway_info.sort()

    proxy_cfg = subprocess.check_output(['cat', '/home/zoeadmin/3proxy.cfg'])
    proxy_decoded = proxy_cfg.decode('utf-8')
    proxy_ports = re.findall(r'-p31\d\d -e192.168.\d{1,3}.100', proxy_decoded)

    proxy_list = []
    for p in proxy_ports:
        try:
            port = p[2:6]
            mip = p.split('.')[2]
            port_int = int(port)
            port_num = port_int - 3127
            temp = [port_num, mip]
            proxy_list.append(temp)
        except:
            pass

    time.sleep(2)
    for p in gateway_info:
        print('---------------------------------------')
        print(f'Proxy No. {num} : setting up IP')
        dev_id = p[0]
        ip_nums = p[1].split('.')
        mid_no = ip_nums[2]
        g_no = ip_nums[3]

        for n in proxy_list:
            if mid_no == n[1]:
                num = str(n[0])
                cmd1 = f'sudo ifconfig {dev_id} 192.168.{mid_no}.100'
                cmd2 = f'sudo ip route add 192.168.{mid_no}.0/24 dev {dev_id} src 192.168.{mid_no}.100 table gw{num}'
                cmd3 = f'sudo ip route add default via 192.168.{mid_no}.{g_no} dev {dev_id} table gw{num}'
                os.system(cmd1)
                time.sleep(1)
                print(f'Proxy No. {num} : setting up routes')
                os.system(cmd2)
                os.system(cmd3)
                time.sleep(1)