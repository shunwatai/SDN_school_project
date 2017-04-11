# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import  packet, ethernet, arp, ipv4, icmp, tcp, udp # for parse the packets
import array # for parsing the packets
from ryu.lib import pcaplib # for pcap file
import re
import pandas as pd
import numpy as np
from pprint import pprint
import sys
sys.path.append("/home/mininet/ryu/ryu/app/fyp")
import pcap_parsing

class ExampleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ExampleSwitch13, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.mac_to_port = {}

        # initial the pcap file
        self.pcap_writer = pcaplib.Writer(open('c0.pcap', 'wb'))

        self.countHS = 0 # count tcp handshake
        self.tcpsrcdst = []# tcp src dst port        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, 0, match, actions)
    
    def add_flow(self, datapath, priority, timeout, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=timeout, hard_timeout=0, match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # dump the packet into pcap file
        self.pcap_writer.write_pkt(ev.msg.data)

        msg = ev.msg        
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        #print("ETHER: ",dir(eth_pkt))
        dst = eth_pkt.dst
        src = eth_pkt.src        
        
        priority,l2_type,l3_proto,clf_result,sip,dip,sp,dp = self.chkpkt(pkt,ev) # also return QoS later
        print('----',priority,l2_type,l3_proto,clf_result,sip,dip,sp,dp,'----')
        #print("===="*4)
        # type of proto: ethernet, arp, icmp, ipv4, tcp
        #proto_type = None
        #for p in pkt.protocols:  # arp_pkt = pkt.get_protocol(arp.arp) # use this for get proto
            ##print(p.protocol_name)
            ##print(p)
            #proto_type = p.protocol_name # just want to get the last type of proto
        ##print("===="*4)
        #print(proto_type)

        # get the received port number from packet_in message.
        in_port = msg.match['in_port']

        #print("sw: ", dpid, " src: ", src, " dst: ", dst, " in_port: ", in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]
        #actions = [] # empty means DROP

        if clf_result == "norm":
            # install a flow to avoid packet_in next time.
            if out_port != ofproto.OFPP_FLOOD:
                if l3_proto is None: # layer2 arp
                    match = parser.OFPMatch(in_port=in_port, eth_type=l2_type, eth_dst=dst)
                    self.add_flow(datapath, priority, 0, match, actions)
                elif l3_proto==1: # layer3 icmp
                    print("norm icmp")
                    match = parser.OFPMatch(in_port=in_port,eth_type=l2_type,ip_proto=l3_proto,ipv4_src=sip,ipv4_dst=dip,eth_dst=dst)
                    self.add_flow(datapath, priority, 15, match, actions)
                elif l3_proto==6: # layer3 tcp
                    print("norm tcp")
                    match = parser.OFPMatch(in_port=in_port,eth_type=l2_type,ip_proto=l3_proto,ipv4_src=sip,ipv4_dst=dip,eth_dst=dst)
                    self.add_flow(datapath, priority, 15, match, actions)

                #self.add_flow(datapath, priority, 20, match, actions)
             
            # construct packet_out message and send it.
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)
        elif clf_result == "bad":
            match = parser.OFPMatch(in_port=in_port,eth_type=l2_type,ip_proto=l3_proto,ipv4_src=sip,ipv4_dst=dip,eth_dst=dst)
            self.add_flow(datapath, priority, 15, match, actions=[])
        else:
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)

#================Below are the functions I added for classify packets=====================#

    def chkpkt(self, pkt, ev):
        ipv4Dict = {}
        icmpDict = {}
        tcpDict = {}
        httpDict = {}
        ftpDict = {}

        #print(pkt.protocols)

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt != None:
            ipv4Dict['len'] = ev.msg.total_len
            ipv4Dict['version'] = ipv4_pkt.version
            ipv4Dict['ipv4Ihl'] = ipv4_pkt.header_length
            ipv4Dict['ipv4Frg'] = ipv4_pkt.offset
            ipv4Dict['ipv4Tos'] = ipv4_pkt.tos
            ipv4Dict['ipv4Len'] = ipv4_pkt.total_length
            ipv4Dict['ipv4Flg'] = ipv4_pkt.flags
            ipv4Dict['ipv4TTL'] = ipv4_pkt.ttl
            ipv4Dict['ipv4Pro'] = ipv4_pkt.proto
            ipv4Dict['ipv4src'] = ipv4_pkt.src
            ipv4Dict['ipv4dst'] = ipv4_pkt.dst

        icmp_pkt = pkt.get_protocol(icmp.icmp)
        if icmp_pkt != None:
            icmpDict['type'] = icmp_pkt.type
            #icmpDict['code'] = icmp_pkt.code
            #icmpDict['data'] = icmp_pkt.data

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt != None:
            tcpDict['tcpSport'] = tcp_pkt.src_port
            tcpDict['tcpDport'] = tcp_pkt.dst_port
            tcpDict['tcpSeq'] = tcp_pkt.seq
            tcpDict['tcpAck'] = tcp_pkt.ack
            tcpDict['tcpFlgint'] = tcp_pkt.bits
            tcpDict['tcpWnd'] = tcp_pkt.window_size
            tcpDict['tcpOfs'] = tcp_pkt.offset
            #pprint(tcpDict)
            
            ## check same flow here?  
            if len(self.tcpsrcdst) > 0: # check here
                srcport = (tcp_pkt.src_port in self.tcpsrcdst)
                dstport = (tcp_pkt.dst_port in self.tcpsrcdst)                
                if srcport and dstport: # if both src and dst port existed => same flow
                    pass
                    #print('same',tcp_pkt.src_port,tcp_pkt.dst_port)
                else: # new flow detected
                    self.countHS = 0 # reset handshake
                    #print('new',tcp_pkt.src_port,tcp_pkt.dst_port)
            
            # need to think when to reset the list, otherwise it will keep growing
            self.tcpsrcdst.append(tcp_pkt.src_port)
            self.tcpsrcdst.append(tcp_pkt.dst_port)            

        # for http payload
        if (type(pkt.protocols[-1]) == bytes):
            #print(pkt.protocols[-1].decode('ascii','ignore'))
            http_tp = pcap_parsing.parseRaw(0, pkt, httpDict, ftpDict) # get req/resp, just want to ignore resp
            #httpDict['len'] = ev.msg.total_len
            #pprint(httpDict)
            if http_tp == "http_resp":
                httpDict = {} # empty dict
                return (3, 0x800, 6, 'norm', ipv4_pkt.src, ipv4_pkt.dst, tcp_pkt.src_port, tcp_pkt.dst_port)
        #else:
            ##print(pkt.protocols[-1].protocol_name)
            #proto_type = pkt.protocols[-1].protocol_name # ready the type of protocol for the "match" of OFP

        return self.makeDF(ipv4Dict,icmpDict,tcpDict,httpDict,ftpDict)

    def makeDF(self, ipv4Dict,icmpDict,tcpDict,httpDict,ftpDict):
        httpDF=ftpDF=tcpDF=udpDF=dnsDF=ipv4DF=icmpDF=arpDF = pd.DataFrame()
        ipv4DF = pcap_parsing.makeDF(ipv4DF, ipv4Dict)
        icmpDF = pcap_parsing.makeDF(icmpDF, icmpDict)
        tcpDF = pcap_parsing.makeDF(tcpDF, tcpDict)
        httpDF = pcap_parsing.makeDF(httpDF, httpDict)

        return self.processDF(ipv4DF,icmpDF,tcpDF,httpDF)

    def processDF(self,ipv4DF,icmpDF,tcpDF,httpDF):
        #### maybe need if statement for different DF ####
        if icmpDF.empty == False:
            col=["len","ipv4src","ipv4dst","ipv4Len","ipv4TTL","type","ipv4Frg"]
            icmpDF = pd.concat([ipv4DF, icmpDF], axis=1, join_axes=[icmpDF.index])[col]
            #print(icmpDF)
            #self.classify("icmp",icmpDF) # dont check by trained clssifier, no time. 
            ## Just check manually for the ipv4 fragmentation, if yes means pkt too large and reject it
            eth_tp = 0x0800 # ipv4
            ip_pt = 1 # icmpv4
            # check big icmp packet by looking at the fragment fields of ipv4
            if icmpDF.ipv4Frg[0] > 0:
                print('big icmp packet detected!')
                return (99,eth_tp,ip_pt,'bad',ipv4DF.ipv4src.values[0],ipv4DF.ipv4dst.values[0],None,None)
            else:
                return (1,eth_tp,ip_pt,'norm',ipv4DF.ipv4src.values[0],ipv4DF.ipv4dst.values[0],None,None)
        if tcpDF.empty == False:
            tcpDF = pd.concat([ipv4DF,tcpDF], axis=1, join_axes=[tcpDF.index])
            col = ['len','ipv4Ihl','ipv4Tos','ipv4Flg','ipv4Frg','ipv4Len','ipv4TTL','ipv4Pro','ipv4src','ipv4dst','tcpSport','tcpDport','tcpFlgint','tcpOfs','tcpWnd']
            tcpDF = tcpDF[col]
            if httpDF.empty == False: # if packet is http, classify it
                agent = self.classify("http",httpDF)
                eth_tp=0x0800 # ipv4
                ip_pt = 6 # tcp
                if re.match(r'(norm|wget|curl)', agent): # if normal browser, not nmap or others
                    return (2, eth_tp, ip_pt, 'norm', ipv4DF.ipv4src.values[0], ipv4DF.ipv4dst.values[0], tcpDF.tcpSport.values[0], tcpDF.tcpDport.values[0])
                else:
                    print('block',agent,'....')
                    return (99, eth_tp, ip_pt, "bad", ipv4DF.ipv4src.values[0], ipv4DF.ipv4dst.values[0], tcpDF.tcpSport.values[0], tcpDF.tcpDport.values[0])
            else: # just classify the layer4 tcp
                return self.classify("tcp",tcpDF)

        return (1, 0x806, None, 'norm', None,None, None, None) # temp for arp

    def classify(self,proto,df):
        from sklearn import preprocessing
        from sklearn.externals import joblib
        #from sklearn import preprocessing
        print('proto:',proto)
        #print(df)
        if proto == "tcp":
            tcp_packet = preprocessing.scale(df.drop(['ipv4src','ipv4dst'],axis=1))
            tcpclf = joblib.load('tcp_clf_kn.pkl')
            result = tcpclf.predict(tcp_packet)
            result = result[0].split('_') # result sth like 'http_norm_request'
            eth_tp = 0x0800 # ipv4
            ip_pt = 6 # tcp
            if result[1]=='norm': # for QoS, skip 1st 2nd HS
                flg = self.tcpFlg(df.tcpFlgint) # useless, convert the flg bit back to readable str
                self.countHS = self.countHS + 1 # count for the tcp handshake
                info = ''.join(map(str,(self.countHS,') ',df.ipv4src.values[0],':',df.tcpSport.values[0],' -> ',df.ipv4dst.values[0],':',df.tcpDport.values[0],flg.values[0],'(',df.tcpFlgint.values[0],')')))
                print(info) # just print out the ip port tcpFlags
                if self.countHS < 5: # look into first 4 initial handshakes, if not SYN(2) or SYN/ACK(18) or ACK(16) or FIN/ACK(1/17) or FIN/PSH/ACK(25)
                    if df.tcpFlgint.values[0] not in [1,2,16,18,17,24,25]:
                        print('invalid 3 way handshake... blocked')
                        return (99, eth_tp, ip_pt, "bad", df.ipv4src.values[0], df.ipv4dst.values[0], df.tcpSport.values[0], df.tcpDport.values[0])
                if self.countHS > 4:
                    self.countHS = 0
                    return (1, eth_tp, ip_pt, 'norm', df.ipv4src.values[0], df.ipv4dst.values[0], None,None)
                #if re.match(r'(http*)', result[0]):
                return (1, None, None, 'later', None, None, None,None) # delay flow install, mon mon sin
        else:
            self.countHS = 0

        if proto == "http":
            #df.drop(['Accept','Host','httpPath'],axis=1,inplace=True)
            empcol = ['Host',
                      'Accept',
                      'Connection_Keep-Alive',
                      'Connection_keep-alive',
                      'httpMethod_GET',
                      'httpMethod_POST',
                      'httpProto_HTTP/1.0',
                      'httpProto_HTTP/1.1',
                      'uAgentBrowser_Chrome',
                      'uAgentBrowser_Firefox',
                      'uAgentBrowser_Wget',
                      'uAgentBrowser_curl',
                      'uAgentOS_Linux',
                      'uAgentOS_Other',
                      'uAgentOS_Windows 7']
            empDF = pd.DataFrame(columns=empcol)
            new_features = pd.concat([empDF,pd.get_dummies(df)],axis=0,join_axes=[empDF.columns]).fillna(value=0)
            new_features['Host'].fillna(0,inplace=True)
            new_features['Accept'].fillna(0,inplace=True)
            new_features['Host'][new_features.Host!=0] = 1
            new_features['Accept'][new_features.Accept!=0] = 1
            #print(new_features)
            httpclf = joblib.load('http_clf_KN.pkl')
            result = httpclf.predict(new_features)
            print(result)
            return result[0] # return user agent to decide how to handle

    # function for convert tcp control bit to str
    def tcpFlg(self, list_of_flg): #list_of_flg is a pd dataframe
        import operator
        strFlg = []
        flgs = {'URG':32,'ACK':16,'PSH':8,'RST':4,'SYN':2,'FIN':1} # Unskilled Attackers Pester Real Security Folks
        for f in list_of_flg:
            flg = []
            for key,val in sorted(flgs.items(), key=operator.itemgetter(1)): # sort dict by value, (itemgetter(1) 0->by key 1->by value)
                if (f & val) != 0:
                    flg.append(key)
            strFlg.append('/'.join(flg))

        result = pd.DataFrame({'Flag': strFlg})
        result.index = list_of_flg.index
        return result
