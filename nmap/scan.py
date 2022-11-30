#coding:utf-8
import socket, threading, os
ip=[]
for c in range(1, 255 + 1):
    for d in range(1, 255 + 1):
        ip.append('10.101.' + str(c) + '.' + str(d))
def scan(ip,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.01)
    r = sock.connect_ex((ip, port))
    sock.close()
    if r == 0:
        return True
def main(ip):
    port_list = [21, 22, 23, 80, 445, 2049, 3306, 3389, 8080, 8888]
    for port in port_list:
        if scan(ip, port):
            print ip
            os.system('nmap -A -n -Pn ' + ip + '>' + ip + '.txt&')
            return
for i in ip:
    threading.Thread(target=main, args=(i,)).start()