#!/bin/env python

# edit line 264 for the target PCAP file

from IPython.display import display
from scapy.all import *
import socket
import re # regular expression
import pandas as pd
import numpy as np
from user_agents import parse # install: pip3 install pyyaml ua-parser user-agents
import email # parsing the Raw header(http, ftp .....)
from pprint import pprint
from io import StringIO # used with email library for parse the raw header
import os # for set the path saving the pandas dataframe to csv

# make the pandas dataframe, just simply concatinate 2 dataframe
def makeDF(df, py_dict):
    df2 = pd.DataFrame([py_dict])
    df = pd.concat([df,df2])
    return df

# take idx as index for pandas dataset
def dataSetIndexing(ls_of_DF):
    for df in ls_of_DF:
        if df.empty == False:
            df.set_index(keys=['idx'],inplace=True)
            df.index.name = None

# export dataframe to csv file
def df_to_csv(ls_of_DF):
    i = 0 # 0:ipv4 1:icmp 2:tcp 3:http 4:ftp
    ls = ["arp","ipv4","icmp","tcp","udp","dns","http","ftp"]
    path_d = '../csv/'
    for df in ls_of_DF:
        fname = ls[i] + '.csv'
        df.to_csv(os.path.join(path_d, fname))
        i = i + 1

# re initialise dictsss
def reinitDict(ls_of_dict):
    for d in ls_of_dict:
        d = {}

def printDict(d):
    for key, value in sorted(d.items()):
        print(key, value)

# useless, for print out something
def printPkt(pkt, layers):
    for layer in layers:
        print(pkt[layer].name)
        pprint(pkt[layer].fields)
        print("*"*20)

# count the layer inside a given packet(pkt) for parse parse later
def countLayer(pkt):
    count = 0
    layers = []
    while True:
        #print(pkt.getlayer(count).name)
        layers.append(pkt.getlayer(count).name)
        count = count + 1
        if pkt.getlayer(count) == None:
            break
    return layers

def makeDict(idx, pkt, d, t):
    d["idx"] = idx
    d["time"] = pkt.time
    d["len"] = len(pkt)
    if t == "arp":
        d["ethSrc"] = pkt.getlayer(Ether).src
        d["ethDst"] = pkt.getlayer(Ether).dst
        d.update(pkt.getlayer(ARP).fields)
    if t == "ipv4":
        d["ethSrc"] = pkt.getlayer(Ether).src
        d["ethDst"] = pkt.getlayer(Ether).dst
        d["ipv4Src"] = pkt.getlayer(IP).src
        d["ipv4Dst"] = pkt.getlayer(IP).dst
        d["ipv4TTL"] = pkt.getlayer(IP).version
        d["ipv4Ihl"] = pkt.getlayer(IP).ihl
        d["ipv4Tos"] = pkt.getlayer(IP).tos
        d["ipv4Len"] = pkt.getlayer(IP).len
        d["ipv4Flg"] = pkt.getlayer(IP).flags
        d["ipv4Frg"] = pkt.getlayer(IP).frag
        d["ipv4TTL"] = pkt.getlayer(IP).ttl
        d["ipv4Pro"] = pkt.getlayer(IP).proto
    if t == "icmp":
        if pkt.getlayer(ICMP) != None: # handle fragmented IP pkt
            d.update(pkt.getlayer(ICMP).fields)
    if t == "tcp": #or t == "raw":
        d["tcpSport"] = pkt.getlayer(TCP).sport
        d["tcpDport"] = pkt.getlayer(TCP).dport
        d["tcpSeq"] = pkt.getlayer(TCP).seq
        d["tcpAck"] = pkt.getlayer(TCP).ack
        d["tcpOfs"] = pkt.getlayer(TCP).dataofs
        d["tcpFlg"] = pkt.sprintf('%TCP.flags%')
        d["tcpFlgint"] = pkt.getlayer(TCP).flags
        d["tcpWnd"] = pkt.getlayer(TCP).window
    if t == "udp":
        d.update(pkt.getlayer(UDP).fields)
    if t == "dns":
        d.update(pkt.getlayer(DNS).fields)
        if 'an' in d : #an qd ns --> these fields are bytes which make pd error
            d.pop('an')
        if 'qd' in d :
            d.pop('qd')
        if 'ns' in d :
            d.pop('ns')
    return d

# parse FTP header
def parseFTPHeader(line,ftp_cmd,ftpDict):
    ftpFstLn = line.split(' ',maxsplit=1)
    #print("ftp cmd: ", ftpFstLn, "*****"*8)

    if re.match(r'^[0-9]{3}', ftpFstLn[0]): # server response
        ftpDict["respCode"] = re.findall(r'^[0-9]{3}', ftpFstLn[0])[0]
    elif ftpFstLn[0] in ftp_cmd:
        count_1stLine = 0 # 0:CMD 1:param1
        for i in ftpFstLn:
            if count_1stLine == 0:
                ftpDict["cmd"] = i
            else:
                param = "param" + str(count_1stLine)
                ftpDict[param] = i
            count_1stLine = count_1stLine + 1

# parse http header
def parseHTTPHeader(firstLine,header,http_methods,httpDict):
    #header = header.split('\n',1)
    if len(header) > 1 and firstLine[0] in http_methods: # parse request header
        #firstLine = header
        headers = header
        message = email.message_from_file(StringIO(headers))
        headers = dict(message.items())
        #pprint(headers)
        if 'User-Agent' in headers:
            user_agent = parse(headers.pop('User-Agent'))
            #print(user_agent)
            #os = re.findall("\((.*?)\)",headers.pop('User-Agent'))[0].split(';') # [0] for take 1st ele in list as str for split
            #browser = splitedAttr[1].split()[-1]
            httpDict["uAgentOS"] = user_agent.os.family # OS
            httpDict["uAgentBrowser"] = user_agent.browser.family #+" "+ user_agent.browser.version_string # browser

        for key,value in headers.items():
            httpDict[key] = value
    #else:
    #    print(header)

    if len(firstLine) > 1:
        #print(firstLine)
        if re.match(r'HTTP/.+', firstLine[0]): # server response
            count_1stLine = 0 # 0:http version(ignored) 1:code 2:msg
            for i in firstLine:
                if count_1stLine == 1:
                    httpDict["respCode"] = i
                if count_1stLine == 2:
                    httpDict["respMsg"] = ' '.join(firstLine[2:])
                count_1stLine = count_1stLine + 1
        elif firstLine[0] in http_methods: # client request
            count_1stLine = 0 # 0:method 1:path 2:http version
            for i in firstLine:
                if count_1stLine == 0:
                    httpDict["httpMethod"] = i
                if count_1stLine == 1:
                    httpDict["httpPath"] = i
                if count_1stLine == 2:
                    httpDict["httpProto"] = i.strip()
                count_1stLine = count_1stLine + 1

# parse packet, return list of protocols
def parsePkt(idx, pkt, layers, serverMAC):
    httpDict={}
    ftpDict={}
    tcpDict={}
    udpDict={}
    dnsDict={}
    ipv4Dict={}
    icmpDict={}
    arpDict={}
    proto_list = []
    ls_of_dict = []
    #printPkt(pkt, layers)

    if pkt.haslayer(Ether):
        #if pkt.getlayer(Ether).src not in serverMAC: # filter out all server, just client request
            #print(pkt.getlayer(Ether).dst, pkt.getlayer(IP).dst) # print client MAC, IP
            if pkt.getlayer(Ether).type == 2048: # 2048(ipv4) 2054(arp)
                #print(pkt.summary)
                proto_list.append("ipv4")
                ipv4Dict = makeDict(idx, pkt, ipv4Dict, "ipv4")
                if pkt.getlayer(IP).proto == 6: # 1(icmp) 6(tcp) 17(udp)
                    proto_list.append("tcp")
                    #print(pkt.getlayer(TCP).show())
                    tcpDict = makeDict(idx, pkt, tcpDict, "tcp") # make dict for tcp, then process raw data on nx line
                    if pkt.haslayer(Raw):
                        proto_list.append(parseRaw(idx, pkt,httpDict,ftpDict))
                if pkt.getlayer(IP).proto == 1:
                    proto_list.append("icmp")
                    icmpDict = makeDict(idx, pkt, icmpDict, "icmp")
                if pkt.getlayer(IP).proto == 17:
                    proto_list.append("udp")
                    #printPkt(pkt, layers)
                    udpDict = makeDict(idx, pkt, udpDict, "udp")
                    if pkt.haslayer(DNS):
                        proto_list.append("dns")
                        dnsDict = makeDict(idx, pkt, dnsDict, "dns")
            if pkt.getlayer(Ether).type == 2054:
                proto_list.append("arp")
                arpDict = makeDict(idx, pkt, arpDict, "arp")
            ls_of_dict = [arpDict,ipv4Dict,icmpDict,tcpDict,udpDict,dnsDict,httpDict,ftpDict]
            return (proto_list,ls_of_dict)
        #else:
        #    return('server')
    else:
        ls_of_dict = [arpDict,ipv4Dict,icmpDict,tcpDict,udpDict,dnsDict,httpDict,ftpDict]
        return (proto_list,ls_of_dict)

# Parse the raw layer header, maybe classify the header here, http,ftp,smtp etc. return str
def parseRaw(idx, pkt, httpDict, ftpDict):
    tp = ""
    if type(pkt) == Ether:
        rawLayer = pkt.getlayer(Raw)
        raw = rawLayer.load.decode('ascii','ignore')
    else:
        pass
        #from ryu.lib.packet import  packet, ethernet, arp, ipv4, icmp, tcp, udp
    #splitedRaw = raw.splitlines() # split header line by line
    splitedRaw = raw.split('\r\n',1) # just split out the first line
    #print(">> ",raw)
    firstLine = splitedRaw[0].split() # split the first line of header by space

    #print(">> ",firstLine)
    if len(firstLine) > 0  and len(splitedRaw) > 1:
        ################ HTTP ##############################
        http_methods = ['GET','POST','HEAD','PUT','CHECKOUT','DELETE','LINK','UNLINK','CHECKIN','TEXTSEARCH','SPACEJUMP','SEARCH']
        if firstLine[0] in http_methods or re.match(r'HTTP/.+', firstLine[0]): #
            parseHTTPHeader(firstLine,splitedRaw[1],http_methods,httpDict)
            httpDict = makeDict(idx, pkt, httpDict, "raw")
            tp = "http"
        else:
            tp = "httpRaw"
        ################ FTP ##############################
        ftp_cmd = ['ABOR','ACCT','ADAT','ALLO','APPE','AUTH','CCC','CDUP','CONF','CWD','DELE','ENC','EPRT','EPSV','FEAT','HELP','HOST','LANG','LIST','LPRT','LPSV','MDTM','MIC','MKD','MLSD','MLST','MODE','NLST','NOOP','OPTS','PASS','PASV','PBSZ','PORT','PROT','PWD','QUIT','REIN','REST','RETR','RMD','RNFR','RNTO','SITE','SIZE','SMNT','STAT','STOR','STOU','STRU','SYST','TYPE','USER','XCUP','XMKD','XPWD','XRCP','XRMD','XRSQ','XSEM','XSEN']
        if firstLine[0] in ftp_cmd or re.match(r'^[0-9]{3}', firstLine[0]): # ftp request
            parseFTPHeader(splitedRaw[0],ftp_cmd,ftpDict)
            ftpDict = makeDict(idx, pkt, ftpDict, "raw")
            tp = "ftp"
    if pkt.haslayer(Padding):
        #print(pkt.haslayer(Padding))
        tp = "padding"
    return tp


"""^^^^^^^^^ Above functions ^^^^^^^^^^"""
"""vvvvvvvvv Below Main vvvvvvvvv"""
def main():
    httpDF=ftpDF=tcpDF=udpDF=dnsDF=ipv4DF=icmpDF=arpDF = pd.DataFrame()

    serverIP = ['127.0.0.1','192.168.238.229','124.248.216.4','192.168.11.123']
    serverMAC = ['00:22:15:8b:e3:ba','00:22:15:26:f0:8d','00:0c:29:94:68:03','00:1d:aa:81:63:30']
    pcap = 'icmp_big_linux.pcap' #firefox_http.pcap,chrome_http.pcap,icmp_80_arp.pcap,ftp_login.pcap,arp_dns.pcap
    with PcapReader(pcap) as pcap_reader:
        index = 1
        for pkt in pcap_reader:
            layers = None #countLayer(pkt)
            pkt_type,ls_of_dict = parsePkt(index,pkt,layers,serverMAC)
            arpDict,ipv4Dict,icmpDict,tcpDict,udpDict,dnsDict,httpDict,ftpDict = ls_of_dict
            #print(index,pkt_type)
            #pprint(httpDict)
            index = index + 1
            if pkt_type is not None:
                if 'http' in pkt_type:
                    httpDF = makeDF(httpDF, httpDict)
                if 'ftp' in pkt_type:
                    ftpDF = makeDF(ftpDF, ftpDict)
                if 'tcp' in pkt_type:
                    tcpDF = makeDF(tcpDF, tcpDict)
                if 'udp' in pkt_type:
                    udpDF = makeDF(udpDF, udpDict)
                if 'dns' in pkt_type:
                    dnsDF = makeDF(dnsDF, dnsDict)
                if 'ipv4' in pkt_type:
                    ipv4DF = makeDF(ipv4DF, ipv4Dict)
                if 'icmp' in pkt_type:
                    icmpDF = makeDF(icmpDF, icmpDict)
                if 'arp' in pkt_type:
                    arpDF = makeDF(arpDF, arpDict)
            #print("=-"*20)
            reinitDict(ls_of_dict) # reinitialise dict for next packet
            #if index == 100: # work for first 100 packets of the PCAP only
            #    break

    ls_of_DF = [arpDF,ipv4DF,icmpDF,tcpDF,udpDF,dnsDF,httpDF,ftpDF]
    dataSetIndexing(ls_of_DF)
    df_to_csv(ls_of_DF)

    #fcol = ['time','ipv4TTL','tcpSport','tcpDport','tcpFlg','tcpWnd','cmd','param1']
    #ftpDF[fcol]
    #col = ["len","ethType","ipv4Src","ipv4Dst","ipv4TTL","ipv4Ihl","ipv4Tos","ipv4Len","ipv4Flg","ipv4Frg","ipv4TTL","ipv4Pro","tcpSport","tcpDport","tcpSeq","tcpAck","tcpOfs","tcpFlg","tcpWnd"]
    #result = pd.concat([ipv4DF, icmpDF], axis=1, join_axes=[icmpDF.index])
    #display(result[col])

    #print(udpDF.columns)
    print('total packet:', index)
    print("Finish!!!")
    #display(httpDF[httpDF.httpMethod.notnull()])
    #display(tcpDF)
    #display(ipv4DF)
    #col=["len","ipv4Flg","ipv4Frg","ipv4Frg","ipv4Len","ipv4TTL","type"]

if __name__ == "__main__":
    get_ipython().magic('time main()')
