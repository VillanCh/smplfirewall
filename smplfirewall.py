#!/usr/bin/env python
#coding:utf-8
"""
  Author:   --<v1ll4n>
  Purpose: Firewall Main
  Created: 2016/12/22
"""

import unittest
import types
from pprint import pprint
from IPy import IP
from os import popen
from netfilterqueue import NetfilterQueue
from scapy.all import IP as IPPacket
from scapy.packet import NoPayload

from netifaces import interfaces
from netifaces import ifaddresses

def get_if_info():
    """Get All Interface information!"""
    result = {}
    for i in interfaces():
        result[i] = ifaddresses(i)[2]
    
    return result

class RuleIP(object):
    """"""
    
    def __init__(self, IP_addr, ports=[], proto=[]):
        """"""
        assert isinstance(ports, types.StringTypes +\
                          (types.TupleType, types.ListType,\
                           types.GeneratorType) ), '[!] Error Ports Type'+\
               '\n You can input a number or iter to gen numbers!\n'
        
        self._ip = IP(IP_addr)
        self._ports = ports if ports else []
    
    @property
    def ip(self):
        return str(self._ip)

    @property
    def strDec(self):
        return self._ip.strDec()
    
    @property
    def strHex(self):
        return self._ip.strHex()
    
    @property
    def ports(self):
        return self._ports

class SmplFireWall(object):
    """Simple Fire Wall Based On NetFilterQueue"""
    
    _instance = None
    _rule_table = {}
    _nf_running = False
    
    _netfilter_obj = None
    
    def __init__(self):
        """"""
        self._if_info = get_if_info()
        if self._rule_table == {}:
            self._init_rule_table()
        else:
            pass
        
        if self._nf_running:
            pass
        else:
            try:
                self._init_start_filterqueue()
                self._nf_running = True
            except RuntimeError:
                pass
            
    
    def _init_start_filterqueue(self):
        """"""
        pprint('[!] Start NfQueueBind')
        for i in self._if_info.items():
            if i[0] == 'lo':
                continue
            dest = IP('{0}/{1}'.format(i[1][0]['addr'], i[1][0]['netmask']), make_net=True)
        
            with popen('iptables -I INPUT -d {0} -j NFQUEUE --queue-num 1'.format(dest)) \
                 as fp:
                if fp.readlines() == []:
                    pass
                else:
                    raise RuntimeError('[!] NetfilterQueue Bind Error!')
                
    
    def _init_rule_table(self):
        """Init rule table"""
        self._rule_table['accept'] = {}
        self._rule_table['accept']['dIP'] = {}
        self._rule_table['accept']['sIP'] = {}
        
        self._rule_table['reject'] = {}
        self._rule_table['reject']['dIP'] = {}
        self._rule_table['reject']['sIP'] = {}
    
    def __new__(cls, *args, **kwargs):
        """Build the Singleton"""
        if cls._instance:
            pass
        else:
            cls._instance = super(SmplFireWall, cls) \
                .__new__(cls, *args, **kwargs)
        return cls._instance
    
    def clearing_nfqueue_bind(self):
        pprint('[!] DELETE NFQUEUEBIND')
        with popen('iptables -F') as fp:
            if fp.readlines() == []:
                pass
            else:
                raise RuntimeError('[!] NetfilterQueue Delete Error!')         
    
    def __del__(self):
        """"""
        self.clearing_nfqueue_bind()
    
    def _filter(self, packet):
        """Process the Packet, Determine Accept or Drop"""
        ret = IPPacket(packet.get_payload())
        #pprint(dir(ret))
        if self._filt_by_table(ret):
            print('Accept')
            packet.accept()
        else:
            packet.drop()
    
    def _filt_by_table(self, ret):
        protocals = []
        _protocal = ret.name
        protocals.append(_protocal)
        filter_param = {}
        filter_param['dIP'] = ret.fields['dst']
        filter_param['sIP'] = ret.fields['src']
        filter_param['protocols'] = protocals
        
        _bufferpacket = ret
        while True:
            _bufferpacket = getattr(_bufferpacket, 'payload')
            #print _bufferpacket
            if isinstance(_bufferpacket, NoPayload):
                break
            else:
                _prot = _bufferpacket.name
                if _prot == 'UDP' or _prot == 'TCP':
                    filter_param['dport'] = _bufferpacket.fields['dport']
                    filter_param['sport'] = _bufferpacket.fields['sport']
                else:
                    pass
                protocals.append(_prot)
        
        return self._filterit(filter_param)
    
    def _filterit(self, filter_param):
        reject_table = self._rule_table['reject']
        accept_table = self._rule_table['accept']
        
        return True
    
    def sync_start(self):
        self._netfilter_obj = NetfilterQueue()
        self._netfilter_obj.bind(1, self._filter)        
        try:
            self._netfilter_obj.run()
        except KeyboardInterrupt:
            print 'Bye!'
            self.clearing_nfqueue_bind()
            


class SmplFWTest(unittest.case.TestCase):
    """"""
    
    def test_singleton(self):
        """"""
        
        self.assertTrue(SmplFireWall() is SmplFireWall())

    def test_running_test(self):
        """"""
        
        s = SmplFireWall()
        s.sync_start()
        s.clearing_nfqueue_bind()

if __name__ == '__main__':
    unittest.main()