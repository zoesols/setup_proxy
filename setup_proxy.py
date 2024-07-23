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

src_proxy = """#define COPYRIGHT "(c)3APA3A, Vladimir Dubrovin & 3proxy.org\\n"\\
                 "Documentation and sources: https://3proxy.org/\\n"\\
                 "Please read license agreement in \'copying\' file.\\n"\\
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
#define FD_SETSIZE 4096
#endif
#include <signal.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <errno.h>
#endif

#ifdef __CYGWIN__
#include <windows.h>
#define daemonize() FreeConsole()
#define SLEEPTIME 1000
#undef _WIN32
#elif _WIN32
#ifdef errno
#undef errno
#endif
#define errno WSAGetLastError()
#ifdef EAGAIN
#undef EAGAIN
#endif
#define EAGAIN WSAEWOULDBLOCK
#ifdef EINTR
#undef EINTR
#endif
#ifndef EINPROGRESS
#define EINPROGRESS WSAEWOULDBLOCK
#endif
#define EINTR WSAEWOULDBLOCK
#define SLEEPTIME 1
#define usleep Sleep
#define pthread_self GetCurrentThreadId
#define getpid GetCurrentProcessId
#define pthread_t unsigned
#ifndef _WINCE
#define daemonize() FreeConsole()
#else
#define daemonize()
#endif
#define socket(x, y, z) WSASocket(x, y, z, NULL, 0, 0)
#define accept(x, y, z) WSAAccept(x, y, z, NULL, 0)
#define ftruncate chsize
#else
#include <pthread.h>
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 32768
#define sockerror strerror
#endif
void daemonize(void);
#define SLEEPTIME 1000
#ifndef O_BINARY
#define O_BINARY 0
#endif
#endif

#ifndef NOODBC
#ifndef _WIN32
#include <sqltypes.h>
#endif
#include <sql.h>
#include <sqlext.h>
#endif

#ifdef _WIN32
#define strcasecmp stricmp
#define strncasecmp strnicmp
#define seterrno3(x) _set_errno(x)
#else
#define seterrno3(x) (errno = x)
#endif

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif

#ifndef isnumber
#define isnumber(n) (n >= '0' && n <= '9')
#endif

#ifndef ishex
#define ishex(n) ((n >= '0' && n <= '9') || (n >= 'a' && n<='f') || (n >= 'A' && n <= 'F'))
#endif

#define isallowed(n) ((n >= '0' && n <= '9') || (n >= 'a' && n <= 'z') || (n >= 'A' && n <= 'Z') || (n >= '*' && n <= '/') || n == '_')

#include "structures.h"

#define MAXRADIUS 5

#define DEFLOGFORMAT "G%y%m%d%H%M%S.%. %p %E %U %C:%c %R:%r %O %I %h %T"

#define myalloc malloc
#define myfree free
#define myrealloc realloc
#define mystrdup strdup

extern RESOLVFUNC resolvfunc;

extern int wday;
extern time_t basetime;
extern int timetoexit;

extern struct extparam conf;

int sockmap(struct clientparam * param, int timeo, int usesplice);
int socksend(struct clientparam *param, SOCKET sock, unsigned char * buf, int bufsize, int to);
int socksendto(struct clientparam *param, SOCKET sock, struct sockaddr * sin, unsigned char * buf, int bufsize, int to);
int sockrecvfrom(struct clientparam *param, SOCKET sock, struct sockaddr * sin, unsigned char * buf, int bufsize, int to);


int sockgetcharcli(struct clientparam * param, int timeosec, int timeousec);
int sockgetcharsrv(struct clientparam * param, int timeosec, int timeousec);
int sockfillbuffcli(struct clientparam * param, unsigned long size, int timeosec);
int sockfillbuffsrv(struct clientparam * param, unsigned long size, int timeosec);

int sockgetlinebuf(struct clientparam * param, DIRECTION which, unsigned char * buf, int bufsize, int delim, int to);




void dolog(struct clientparam * param, const unsigned char *s);
int dobuf(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec);
int dobuf2(struct clientparam * param, unsigned char * buf, const unsigned char *s, const unsigned char * doublec, struct tm* tm, char * format);
extern FILE * stdlog;
void logstdout(struct clientparam * param, const unsigned char *s);
void logsyslog(struct clientparam * param, const unsigned char *s);
void lognone(struct clientparam * param, const unsigned char *s);
void logradius(struct clientparam * param, const unsigned char *s);

#ifndef NOSQL
void logsql(struct clientparam * param, const unsigned char *s);
int init_sql(char * s);
void close_sql();
#endif
int doconnect(struct clientparam * param);
int alwaysauth(struct clientparam * param);
int ipauth(struct clientparam * param);
int doauth(struct clientparam * param);
int strongauth(struct clientparam * param);
void trafcountfunc(struct clientparam *param);
unsigned bandlimitfunc(struct clientparam *param, unsigned nbytesin, unsigned nbytesout);
int handleredirect(struct clientparam * param, struct ace * acentry);

int scanaddr(const unsigned char *s, unsigned long * ip, unsigned long * mask);
int myinet_ntop(int af, void *src, char *dst, socklen_t size);
extern struct nserver nservers[MAXNSERVERS];
extern struct nserver authnserver;
unsigned long getip(unsigned char *name);
unsigned long getip46(int family, unsigned char *name,  struct sockaddr *sa);
int afdetect(unsigned char *name);
unsigned long myresolver(int, unsigned char *, unsigned char *);
unsigned long fakeresolver (int, unsigned char *, unsigned char*);
int inithashtable(struct hashtable *hashtable, unsigned nhashsize);
void freeparam(struct clientparam * param);
void clearstat(struct clientparam * param);
void dumpcounters(struct trafcount *tl, int counterd);

int startconnlims (struct clientparam *param);
void stopconnlims (struct clientparam *param);



extern struct auth authfuncs[];

int reload (void);
extern int paused;
extern int demon;

unsigned char * mycrypt(const unsigned char *key, const unsigned char *salt, unsigned char *buf);
unsigned char * ntpwdhash (unsigned char *szHash, const unsigned char *szPassword, int tohex);
int de64 (const unsigned char *in, unsigned char *out, int maxlen);
unsigned char* en64 (const unsigned char *in, unsigned char *out, int inlen);
void tohex(unsigned char *in, unsigned char *out, int len);
void fromhex(unsigned char *in, unsigned char *out, int len);



int ftplogin(struct clientparam *param, char *buf, int *inbuf);
int ftpcd(struct clientparam *param, unsigned char* path, char *buf, int *inbuf);
int ftpsyst(struct clientparam *param, unsigned char *buf, unsigned len);
int ftppwd(struct clientparam *param, unsigned char *buf, unsigned len);
int ftptype(struct clientparam *param, unsigned char* f_type);
int ftpres(struct clientparam *param, unsigned char * buf, int len);
SOCKET ftpcommand(struct clientparam *param, unsigned char * command, unsigned char  *arg);


int text2unicode(const char * text, char * buf, int buflen);
void unicode2text(const char *unicode, char * buf, int len);
void genchallenge(struct clientparam *param, char * challenge, char *buf);
void mschap(const unsigned char *win_password,
                 const unsigned char *challenge, unsigned char *response);

struct hashtable;
void hashadd(struct hashtable *ht, const unsigned char* name, unsigned char* value, time_t expires);

int parsehost(int family, unsigned char *host, struct sockaddr *sa);
int parsehostname(char *hostname, struct clientparam *param, unsigned short port);
int parseusername(char *username, struct clientparam *param, int extpasswd);
int parseconnusername(char *username, struct clientparam *param, int extpasswd, unsigned short port);
int ACLmatches(struct ace* acentry, struct clientparam * param);
int checkACL(struct clientparam * param);
extern int havelog;
unsigned long udpresolve(int af, unsigned char * name, unsigned char * value, unsigned *retttl, struct clientparam* param, int makeauth);

struct ace * copyacl (struct ace *ac);
struct auth * copyauth (struct auth *);
void * itfree(void *data, void * retval);
void freeacl(struct ace *ac);
void freeauth(struct auth *);
void freefilter(struct filter *filter);
void freeconf(struct extparam *confp);
struct passwords * copypwl (struct passwords *pwl);
void freepwl(struct passwords *pw);
void copyfilter(struct filter *, struct srvparam *srv);
FILTER_ACTION makefilters (struct srvparam *srv, struct clientparam *param);
FILTER_ACTION handlereqfilters(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p);
FILTER_ACTION handlehdrfilterscli(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p);
FILTER_ACTION handlehdrfilterssrv(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p);
FILTER_ACTION handlepredatflt(struct clientparam *param);
FILTER_ACTION handledatfltcli(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p);
FILTER_ACTION handledatfltsrv(struct clientparam *param, unsigned char ** buf_p, int * bufsize_p, int offset, int * length_p);

void srvinit(struct srvparam * srv, struct clientparam *param);
void srvinit2(struct srvparam * srv, struct clientparam *param);
void srvfree(struct srvparam * srv);
unsigned char * dologname (unsigned char *buf, unsigned char *name, const unsigned char *ext, ROTATION lt, time_t t);
int readconfig(FILE * fp);
int connectwithpoll(struct clientparam *param, SOCKET sock, struct sockaddr *sa, SASIZETYPE size, int to);


int myrand(void * entropy, int len);

extern char *copyright;


#define SERVICES 5

void * dnsprchild(struct clientparam * param);
void * pop3pchild(struct clientparam * param);
void * smtppchild(struct clientparam * param);
void * proxychild(struct clientparam * param);
void * sockschild(struct clientparam * param);
void * tcppmchild(struct clientparam * param);
void * autochild(struct clientparam * param);
void * udppmchild(struct clientparam * param);
void * adminchild(struct clientparam * param);
void * ftpprchild(struct clientparam * param);
void * tlsprchild(struct clientparam * param);


struct datatype;
struct dictionary;
struct node;
struct property;
extern pthread_mutex_t config_mutex;
extern pthread_mutex_t bandlim_mutex;
extern pthread_mutex_t connlim_mutex;
extern pthread_mutex_t hash_mutex;
extern pthread_mutex_t tc_mutex;
extern pthread_mutex_t pwl_mutex;
extern pthread_mutex_t log_mutex;
extern pthread_mutex_t rad_mutex;
extern struct datatype datatypes[64];

extern struct commands commandhandlers[];

#ifdef WITHSPLICE
#define mapsocket(a,b) ((a->srv->usesplice && !a->ndatfilterssrv && !a->ndatfilterscli)?sockmap(a,b,1):sockmap(a,b,0))
#else
#define mapsocket(a,b) sockmap(a,b, 0)
#endif


extern struct radserver {
#ifdef NOIPV6
        struct  sockaddr_in authaddr, logaddr, localaddr;
#else
        struct  sockaddr_in6 authaddr, logaddr, localaddr;
#endif
/*
        SOCKET logsock;
*/
} radiuslist[MAXRADIUS];

extern char radiussecret[64];
extern int nradservers;
extern struct socketoptions {
        int opt;
        char * optname;
} sockopts[];
void setopts(SOCKET s, int opts);
char * printopts(char *sep);

#ifdef _WINCE
char * CEToUnicode (const char *str);
int cesystem(const char *str);
int ceparseargs(const char *str);
extern char * ceargv[32];

#define system(S) cesystem(S)
#endif

#define WEBBANNERS 35

#endif

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
6 gw6
7 gw7
8 gw8
9 gw9
10 gw10
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
    print('---------------------------------------')
    print('[Test]')
    start_proxy_port = 3128
    for t in gateway_info:
        print('---------------------------------------')
        print(f'Proxy Port : {start_proxy_port}')
        test_cmd = f'sudo curl https://wtfismyip.com/text'
        os.system(test_cmd)
        start_proxy_port += 1
        
"""
home_path = '/home/' + os.getlogin()
os.chdir(home_path)
print(os.getcwd())

with open("/etc/sysctl.conf", "w") as f:
    f.write(sysctl_conf)

os.system('sudo apt -y install fail2ban software-properties-common build-essential libevent-dev libssl-dev curl')
time.sleep(10)
os.system('git clone https://github.com/3proxy/3proxy.git')
time.sleep(2)
os.chdir(home_path + '/3proxy')

with open("src/proxy.h", "w") as f:
    f.write(src_proxy)

os.system('sudo ln -s Makefile.Linux Makefile')
time.sleep(1)
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