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

from operator import attrgetter

#from ryu.app import simple_switch_13
import sys
sys.path.append("/home/mininet/ryu/ryu/app/fyp")
import example_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub


class SimpleMonitor13(example_switch_13.ExampleSwitch13):
    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.rx = {}
        self.tx = {}
        self.itvl = 5 # monitor update interval
        self.flow_alert = 0 # counter for flow alert
        self.icmp_thresh = 100 # threshold for icmp
        self.tcp_thresh = 1000 # threshold for tcp

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(self.itvl)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        body = ev.msg.body
        print()
        print("----- flow stat -----")
        #print(body)

        self.logger.info('datapath   '
                         'in-port eth-dst           '
                         'out-port packets  bytes     type  duration')
        self.logger.info('--------   '
                         '------- ----------------- '
                         '-------- -------- --------  ----  --------')

        for stat in sorted([flow for flow in body if flow.priority >= 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            #print(stat)
            byte_interval = 0
            pkt_interval = 0
            if stat.duration_sec > 0: # for get the avg byte and pkt
                byte_interval = (stat.byte_count * self.itvl) / stat.duration_sec
                pkt_interval = (stat.packet_count * self.itvl) / stat.duration_sec
            else: # new flow duration == 0, avoid divided by zero
                byte_interval = stat.byte_count
                pkt_interval = stat.packet_count
            if len(stat.instructions) == 0: # equals to 0 mean drop rules and NO stat.instructions
                out_port = -1 # I chose -1 indicate as None
                act_type = -1 # I chose -1 indicate as Drop
            else:
                out_port = stat.instructions[0].actions[0].port
                act_type = stat.instructions[0].actions[0].type

                # trying to generate alarm for flooding attack and then insert "drop" action
                if stat.match['eth_type'] == 2048: # ipv4
                    in_port = stat.match['in_port']
                    l2_type = stat.match['eth_type']
                    l3_proto = stat.match['ip_proto']
                    sip = stat.match['ipv4_src']
                    dip = stat.match['ipv4_dst']
                    dst = stat.match['eth_dst']
                    priority = 99
                    if stat.match['ip_proto'] == 1: # icmp
                        #print('avg_pkt:',pkt_interval,'thr:',self.icmp_thresh,'alt:',self.flow_alert)
                        if pkt_interval > self.icmp_thresh:
                            self.icmp_thresh = (pkt_interval+1) * 1.1
                            self.flow_alert = self.flow_alert + 1 # alert + 1
                            print("ICMP Alert x ",self.flow_alert)
                            ## think how to insert drop action flow entry
                            if self.flow_alert > 3: # install frop action flow entry
                                match = parser.OFPMatch(in_port=in_port,eth_type=l2_type,ip_proto=l3_proto,ipv4_src=sip,ipv4_dst=dip,eth_dst=dst)
                                self.add_flow(datapath, priority, 15, match, actions=[])
                                self.flow_alert = 0  # reset alert
                        else: # reset threshold
                            self.icmp_thresh = 100
                    if stat.match['ip_proto'] == 6: # tcp
                        if pkt_interval > self.tcp_thresh:
                            self.tcp_thresh = (pkt_interval+1) * 1.1
                            self.flow_alert = self.flow_alert + 1 # alert + 1
                            print("TCP Alert x ",self.flow_alert)
                            ## think how to insert drop action flow entry
                            if self.flow_alert > 3: # install frop action flow entry
                                match = parser.OFPMatch(in_port=in_port,eth_type=l2_type,ip_proto=l3_proto,ipv4_src=sip,ipv4_dst=dip,eth_dst=dst)
                                self.add_flow(datapath, priority, 15, match, actions=[])
                                self.flow_alert = 0  # reset alert
                        else: # reset threshold
                            self.tcp_thresh = 100

            # print out the table
            self.logger.info('%04x %13x %17s %8x %8d %8d %5d %9d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             out_port,
                             pkt_interval, byte_interval,
                             act_type,
                             stat.duration_sec)

        print()

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        print("----- port stat -----")
        self.logger.info('switch#    port#    '
                         'rxPkt  rxBytes    '
                         'txPkt  txBytes ')
        self.logger.info('-------  -------  '
                         '-------  -------  '
                         '-------  -------')
        #print(body)
        for stat in sorted(body[0:-1], key=attrgetter('port_no')):
            if stat.port_no in self.rx or stat.port_no in self.tx: # if port not in dict, goto else to init
                r_packets = stat.rx_packets - self.rx[stat.port_no]['tmp_pkt'] # diff = latest - last updated
                t_packets = stat.tx_packets - self.tx[stat.port_no]['tmp_pkt'] # diff = latest - last updated
                if r_packets == 0: # if nothing change means no traffic, so 0
                    self.rx[stat.port_no]['no_pkt'] = 0 # RX pkt
                    self.rx[stat.port_no]['rbytes'] = 0 # RX byte
                    self.tx[stat.port_no]['no_pkt'] = 0 # TX .
                    self.tx[stat.port_no]['tbytes'] = 0 # TX .
                else: # update info
                    self.rx[stat.port_no]['no_pkt'] = r_packets # update diff for print
                    self.rx[stat.port_no]['tmp_pkt'] = stat.rx_packets # update latest total r_pkt
                    self.rx[stat.port_no]['rbytes'] = stat.rx_bytes - self.rx[stat.port_no]['tmp_rbytes'] # update diff of r_bytes for print
                    self.rx[stat.port_no]['tmp_rbytes'] = stat.rx_bytes # update latest total r_bytes
                    ##################
                    self.tx[stat.port_no]['no_pkt'] = t_packets # update diff for print
                    self.tx[stat.port_no]['tmp_pkt'] = stat.tx_packets # update latest total r_pkt
                    self.tx[stat.port_no]['tbytes'] = stat.tx_bytes - self.tx[stat.port_no]['tmp_tbytes'] # update diff of t_bytes for print
                    self.tx[stat.port_no]['tmp_tbytes'] = stat.tx_bytes # update latest total t_bytes
            else: # init
                self.rx[stat.port_no] = {}
                self.rx[stat.port_no]['no_pkt'] = 0
                self.rx[stat.port_no]['tmp_pkt'] = stat.rx_packets
                self.rx[stat.port_no]['rbytes'] = 0
                self.rx[stat.port_no]['tmp_rbytes'] = stat.rx_bytes

                self.tx[stat.port_no] = {}
                self.tx[stat.port_no]['no_pkt'] = 0
                self.tx[stat.port_no]['tmp_pkt'] = stat.tx_packets
                self.tx[stat.port_no]['tbytes'] = 0
                self.tx[stat.port_no]['tmp_tbytes'] = stat.tx_bytes
            #print(stat.port_no,": ",self.rx[stat.port_no]['no_pkt'],", ",self.rx[stat.port_no]['rbytes'])
            self.logger.info('%7x %8x %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             self.rx[stat.port_no]['no_pkt'], self.rx[stat.port_no]['rbytes'],
                             self.tx[stat.port_no]['no_pkt'], self.tx[stat.port_no]['tbytes'])
            #print("--- transmit ---")
            #print(stat.port_no,": ",stat.tx_packets,", ",stat.tx_bytes)

        """
        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)
        """
