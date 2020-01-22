import re
import os
import sys
import time
import logging
import subprocess
import socket
import nmap
import requests
import iptc
from scapy.all import sniff
from bs4 import BeautifulSoup
from bs4 import Comment
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
######################### LISTS #######################
def pr_list(x):
    mn1=["Parse log file","Monitor directory","Scan network","Detect attacks","Scrub domain"]
    mn2=["Full result","Uniqe URIs","Uniqe IPs","Uniqe User Agents"]
    mn3=["show in screen","Save to file"]
    menu=[mn1,mn2,mn3]
    n=0;j=-1
    print("Choose option:")
    while j not in range(1,len(menu[x])+1):
        for i in menu[x]:
            n+=1
            print(str(n)+"- "+i)
        n=0
        try:
            j=int(input("Choise: "))
            os.system("clear")
        except KeyboardInterrupt:
            exit()
        except:
            j=-1
            os.system("clear")
    return j
######################### PARSING #####################
def file_open():
    fi=input("write the full path of your log file:\n")
    try:
        f=open(fi,"r")
        st=f.read()
        return st
    except:
        print("Error occured while opening file,The program will exit")
        exit()  
def get_info(st):
    try:
        d={}
        x=re.findall(r"(\s\/.+?\s)",st)
        d["uri"]=x
        y=re.findall(r"(\d.+?\s-)",st)
        d["ip"]=y
        v=re.findall(r"\"[A-Z]{3}\s|\"[A-Z]{4}\s",st)
        d["method"]=v
        w=re.findall(r"\"[A-z][a-z]+\/\d.+?\"",st)
        d["ua"]=w
        return d
    except:
        print("Error occured while filtering file,The program will exit")
        exit()    
def pr_fun(pr,sv,key=' '):
    if key !=' ':
        try:
            n=0;flag=0
            z=set(pr[key])
            for i in z:
                n+=1
                if sv == 1:
                    print(str(n)+" - "+str(i[0:-1]))
                elif sv == 2:
                    try:
                        if n==1:
                            f=open("/root/Desktop/parse.txt",'w')
                            f.write(str(n)+" - "+str(i[0:-1])+"\n")
                            f.close();flag=1
                        else:
                            f=open("/root/Desktop/parse.txt",'a')
                            f.write(str(n)+" - "+str(i[0:-1])+"\n")
                            f.close();flag=1
                    except:
                        print("Cant write to file")
        except:
            print("Error while prenting ")
    if key ==' ':
        n=0
        for i in range(len(pr['uri'])):
            n+=1
            if sv == 1:
                print(str(n)+" - "+str(pr['ip'][i][0:-1])+"  "+str(pr['uri'][i][0:-1])+"  "+str(pr['method'][i][0:-1])+"  "+str(pr['ua'][i][0:-1]))
            if sv == 2:
                try:
                    if n==1:
                        f=open("/root/Desktop/parse.txt",'w')
                        f.write(str(n)+" - "+str(pr['ip'][i][0:-1])+"  "+str(pr['uri'][i][0:-1])+"  "+str(pr['method'][i][0:-1])+"  "+str(pr['ua'][i][0:-1])+"\n")
                        f.close();flag=1
                    else:
                        f=open("/root/Desktop/parse.txt",'a')
                        f.write(str(n)+" - "+str(pr['ip'][i][0:-1])+"  "+str(pr['uri'][i][0:-1])+"  "+str(pr['method'][i][0:-1])+"  "+str(pr['ua'][i][0:-1])+"\n")
                        f.close();flag=1
                except:
                    print("Cant write to file")
    if flag == 1:
        print("successful")
######################### MONITOR #####################
def dir_mon(sv):
    try:
        if sv ==1:
            logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S')
        elif sv == 2:
            logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s - %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S',filename="/root/Desktop/dir_mon.txt")
    except:
        print("Couldnt create file program will")
        exit()
    try:
        path = input("Enter full path of monitered directory:")
        event_handler = LoggingEventHandler()
        observer = Observer()
        observer.schedule(event_handler, path, recursive=True)
        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
    except:
        print("couldnt monitor given input program will exit")
######################### SCANNER #####################
def scan_up():
    up_hosts=[]
    try:
        ips=subprocess.Popen("arp-scan -l",shell=True, stdout=subprocess.PIPE,stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        x=str(ips.stdout.read(),"utf-8")
        up_ips=re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",x)
    except:
        print("error while scanning IPs in network")
        exit()
    for i in up_ips:
        up=os.system("ping -W 1 -c1 "+i+">/dev/null 2>&1")
        if up == 0:
            up_hosts+=[i]
            print (i+" is up")
    up_hosts=set(up_hosts)
    print ("number of up hosts : "+str(len(up_ips)))
    port1=0;port2=0;target=[]
    while port1 not in range(1,65536):
        try:
            port1=int(input("Enter start port number(1-65535): "))
        except:
            os.system("clear")
            print("Only numbers are accepted")
            port1=0

    while port2 not in range(port1,65536):
        try:
            port2=int(input("Enter end port number("+str(port1)+"-65535): "))
            os.system("clear")
        except:
            os.system("clear")
            print("Only numbers are accepted")
            port2=0
    for i in up_hosts:
        for j in range(port1,port2+1):
            target+=[(i,j)]
    return target
def scan_port(target,sv):
    comp='';tmp='';n=0;nm=nmap.PortScanner()
    for i in target:
        tmp=[i[0]];n+=1
        if tmp!=comp:
            
            comp=tmp
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.1)
        x=s.connect_ex(tuple(i))
        if x==0:
            try:
                nm.scan(i[0], str(i[1]),arguments='-sC -sV')
                lin=(nm.csv().split("\n"))
                lin2=lin[1].split(";")
                lin=[]
                valid=[0,3,4,5,7,10]
                for m in range(len(lin2)):
                    if m in valid:
                        lin.append(lin2[m])
                lin2=" ".join(lin)
            except:
                print("Couldnt pass output to nmap")
            if sv ==1:
                print(lin2)
            else :
                try:
                    f=open("/root/Desktop/scan.txt",'a')
                    f.write(lin2+"\n")
                    f.close()
                except:
                    print("Couldnt write to file")
                    exit()
        s.close()
######################### SCRUBER #####################
def connect(inp):
    headers = requests.utils.default_headers()
    headers.update({ 'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'})
    try:
        res=requests.get(inp,headers)
        x=res.content
        soup=BeautifulSoup(x,"lxml")
        return(soup)
    except:
        print("failed to connect to the URL provided")
        exit()
def get_tags(soup,sv):
    tags=[];n=0;op=[]
    if sv == 1:
        print("---------------------- UNIQUE TAGS ---------------------\n")
    elif sv ==2:
        try:
            f=open("/root/Desktop/scrub.txt",'w')
            f.write("---------------------- UNIQUE TAGS ---------------------\n")
            f.close() 
        except:
            print("Cant write to file")
    tags=soup.findAll()
    for i in tags:
        op+=[i.name]
    op =list(set(op))
    for i in op:
        n+=1
        if sv ==1:
            print(str(n)+"- <"+i+">")
        elif sv ==2:
            f=open("/root/Desktop/scrub.txt",'a')
            f.write(str(n)+"- <"+i+">\n")
            f.close()          
def get_urls(soup,sv):
    urls=[]
    if sv == 1:
        print("---------------------- UNIQUE URLS ---------------------\n")
    elif sv ==2:
        f=open("/root/Desktop/scrub.txt",'a')
        f.write("---------------------- UNIQUE URLS ---------------------\n")
        f.close() 
    n=0
    for link in soup.find_all('a'):
        urls.append(link.get('href'))
    urls = list(set(urls))
    for i in urls:
        n+=1
        if sv==1:
            print(str(n)+"- "+str(i)+"\n")
        elif sv==2:
            f=open("/root/Desktop/scrub.txt",'a')
            f.write(str(n)+"- "+str(i)+"\n")
            f.close()
    urls ="\n".join(str(urls))
    return (urls)
def get_comments(soup,sv):
    comments=[]
    if sv == 1:
        print("---------------------- UNIQUE COMMENTS ---------------------\n")
    elif sv ==2:
        f=open("/root/Desktop/scrub.txt",'a')
        f.write("---------------------- UNIQUE COMMENTS ---------------------\n")
        f.close() 
    n=0
    for link in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comments.append(link)
    comments=list(set(comments))
    for i in comments:
        n+=1
        if sv==1:
            print(str(n)+"- "+i+"\n")
        elif sv==2:
            f=open("/root/Desktop/scrub.txt",'a')
            f.write(str(n)+"- "+i+"\n")
            f.close()
def get_subdomains(url,dom,sv):
    inp2=dom.split('.')
    inp2='.'.join(inp2[1:])
    if sv ==1:
        print("--------------------- UNIQUE SUB DOMAINS-------------------------\n")
    elif sv==2:
        f=open("/root/Desktop/scrub.txt",'a')
        f.write("--------------------- UNIQUE SUB DOMAINS-------------------------\n")
        f.close()
    reg= r"(https:\/\/\S+?|www\.\S+?|http:\/\/\S+?)"+inp2
    x=re.findall(reg,url);n=0
    x=list(set(x))
    for i in x:
        i='.'.join(i.split('.'))[:-1]
        try:
            i=i.split("//")[1]
        except:
            pass
        n+=1
        if sv==1:
            print(str(n)+"- "+i+"\n")
        elif sv==2:
            f=open("/root/Desktop/scrub.txt",'a')
            f.write(str(n)+"- "+i+"\n")
            f.close()
#################### ATTACK DETECTION #################
def open_again(port):
    os.system("nc -nvlp " + str(port) + " &")
    os.system("clear")
def unknown_ports():
    global myIP
    host = socket.gethostbyname(myIP)
    openPorts = []
    for port in range(1, 30000):
        if port not in wellknown and port < 30000:
            scannerTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(0.1)
            status = scannerTCP.connect_ex((host, port))
            if not status:
                openPorts.append(port) 
    for p in openPorts:
        os.system("nc -nvlp " + str(p) + " &")
        os.system("clear")   
    return openPorts
def blockIP(ip):
    #add rule to iptables-legacy
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
    rule = iptc.Rule()
    rule.in_interface = "eth0"
    target = iptc.Target(rule, "DROP")
    rule.target = target
    rule.src = ip  # ip in string format
    chain.insert_rule(rule)

    os.system(f"iptables -A OUTPUT -d {ip} -j DROP") #add a rule to iptables as well
def printall(pkt):
    global myIP
    global unKnown
    tcp_sport = ""
    if 'TCP' in pkt:
        tcp_sport=pkt['TCP'].sport

    if (pkt['IP'].src == myIP)  and tcp_sport in unKnown:
        blockIP(pkt['IP'].dst)
        open_again(tcp_sport)
        print("Attack detected!")
        print(f"Blocking {pkt['IP'].dst} ...\nBlocked!\n")
def Monitor():
    sniff(filter="ip",prn=printall)
    sniff(filter="ip and host " + myIP, prn=printall)
########################## MAIN #######################
if __name__ == "__main__":
    inp=pr_list(0)
    # Parsing
    if inp == 1:
        st=file_open()
        y=get_info(st)   
        inp=pr_list(1)
        if inp == 1:
            inp=pr_list(2)
            pr_fun(y,inp)
        elif inp == 2:
            inp=pr_list(2)
            pr_fun(y,inp,'uri')
        elif inp == 3:
            inp=pr_list(2)
            pr_fun(y,inp,'ip')
        elif inp == 4:
            inp=pr_list(2)
            pr_fun(y,inp,'ua')
    #Directory monitor
    elif inp == 2:
        inp = pr_list(2)
        dir_mon(inp)
    #Scanner
    elif inp == 3:
        inp = pr_list(2)
        tar=scan_up()
        scan_port(tar,inp)
    #Attack detect
    elif inp == 4:
        wellknown = [1, 5, 7, 18, 20, 21, 22, 23, 25, 29, 37, 42, 43, 49, 53,
                    69, 70, 79, 80, 103, 108, 109, 110, 115, 118, 119, 137, 139, 143,
                    150, 156, 161, 179, 190, 194, 197, 389, 396, 443, 444, 445, 458, 546, 547, 563, 569, 1080]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        myIP = s.getsockname()[0]
        s.close()
        unKnown = unknown_ports()
        if(len(unKnown)):
            print(f"Monitoring {myIP}....")
            Monitor()
        else:
            print("No Open ports were detected\ngo open some first ;)")
    #Scruber
    elif inp ==5:
        inp = pr_list(2)
        inp1=input("Enter the URL(http://www.example.com):\n")
        soup=connect(inp1)
        get_tags(soup,inp)
        u_urls=get_urls(soup,inp)
        get_subdomains(str(soup),inp1,inp)
        get_comments(soup,inp)