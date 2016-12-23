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
from scapy.all import IP as IPPacket
from scapy.packet import NoPayload
import nfqueue
import socket

from ConfigParser import ConfigParser

from netifaces import interfaces
from netifaces import ifaddresses

def get_if_info():
    """Get All Interface information!"""
    result = {}
    for i in interfaces():
        result[i] = ifaddresses(i)[2]
    
    return result

class Rule(object):
    """"""
    
    def __init__(self, IP_addr, dports=[], sports=[], protos=[]):
        """"""
        assert isinstance(dports, types.StringTypes +\
                          (types.TupleType, types.ListType,\
                           types.GeneratorType) ), '[!] Error Ports Type'+\
               '\n You can input a number or iter to gen numbers!\n'
        
        if IP_addr != "*":
            self._ip = IP(IP_addr)
        else:
            self._ip = '*'
        
        if isinstance(dports, (types.ListType)):
            pass
        else:
            _ = []
            _.append(dports)
            dports = _
        
        if isinstance(sports, (types.ListType)):
            pass
        else:
            _ = []
            _.append(sports)
            sports = _ 
            
        
        if isinstance(protos, (types.ListType)):
            pass
        else:
            _ = []
            _.append(protos)
            dports = _        
        
        self._dports = dports if dports else []
        self._sports = sports if sports else []
        
        self._proto = protos if protos else []
    
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
    def dports(self):
        return self._dports
    
    @property
    def sports(self):
        return self._sports
    
    def __repr__(self):
        return self.ip
    
    @property
    def protocols(self):
        return self._proto
    
    def __add__(self, rule):
        """"""
        assert isinstance(rule, Rule), '[!] Error  Type  rule'
        assert self.ip == rule.ip, '[!] Different IP rule can\'t be added'
        
        self._dports = self._dports + rule.dports
        self._dports = self._sports + rule.sports
        self._proto = self._proto + rule.protocols
        
        return self
    
    
    
class SmplFireWall(object):
    """Simple Fire Wall Based On NetFilterQueue"""
    
    _instance = None
    _rule_table = {}
    _nf_running = False
    
    _netfilter_obj = None
    
    def __init__(self, HOOK_TABLE='OUTPUT'):
        """"""
        self._hook_table = HOOK_TABLE
        
        
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
        
            with popen('iptables -I {0} -d {1} -j NFQUEUE --queue-num 1'.format(self._hook_table, dest)) \
                 as fp:
                if fp.readlines() == []:
                    pass
                else:
                    raise RuntimeError('[!] NetfilterQueue Bind Error!')           
                
    
    def _init_rule_table(self):
        """Init rule table"""
        #self._rule_table['accept'] = {}
        #self._rule_table['accept']['dst'] = {}
        #self._rule_table['accept']['src'] = {}
        
        self._rule_table
        self._rule_table['dst'] = {}
        self._rule_table['src'] = {}
    
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
        ret = IPPacket(packet.get_data())
        #pprint(dir(ret))
        if self._filt_by_table(ret):
            print('Accept : src: ', ret.fields['src'], 'dst: ', ret.fields['dst'])
            try:
                print('sport: ', ret.payload.fields['sport'])
                print('dport: ', ret.payload.fields['dport'])
            except:
                pass
            packet.set_verdict(nfqueue.NF_ACCEPT)
        else:
            print('Reject : src: ', ret.fields['src'], 'dst: ', ret.fields['dst'])#print('Reject : ', ret)
            try:
                print('sport: ', ret.payload.fields['sport'])
                print('dport: ', ret.payload.fields['dport'])
            except:
                pass            
            packet.set_verdict(nfqueue.NF_DROP)
    
    def _filt_by_table(self, ret):
        """Called By self._filter()"""
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
                _prot.lower()
                if filter_param.has_key('dport'):
                    pass
                else:
                    try:
                        filter_param['dport'] = _bufferpacket.fields['dport']
                        filter_param['sport'] = _bufferpacket.fields['sport']
                    except:
                        filter_param['dport'] = -1
                        filter_param['sport'] = -1                
                protocals.append(_prot)
        
        return self._filterit(filter_param)
    
    def _filterit(self, filter_param):
        """Called By self._filt_by_table()"""
        result = True
        result = self._filter_reject(filter_param, origin=result)
        #result = self._filter_accept(filter_param, origin=result)
        return result
    
    
    def _filter_reject(self, filter_param, origin):
        """"""
        result = origin
        #reject_table = self._rule_table['reject']
        
        
        rdsp = self._rule_table['dst']
        if '*' in rdsp.keys():
            return False
        #print rdsp.keys()
        if filter_param['dIP'] in rdsp.keys():
            rdports = rdsp[filter_param['dIP']].dports
            rsports = rdsp[filter_param['dIP']].sports
            rprotos = rdsp[filter_param['dIP']].protocols
            
            if rdports == [] and rsports == [] and rprotos == []:
                result = False
            
            if str(filter_param['dport']) in rdports:
                result = False
            
            if str(filter_param['sport']) in rsports:
                result = False
            
            for i in filter_param['protocols']:
                if i in rprotos:
                    result = False
                    break
                
        rsrc = self._rule_table['src']
        if '*' in rsrc.keys():
            return False
        
        if filter_param['sIP'] in rsrc.keys():
            rdports = rsrc[filter_param['sIP']].dports
            rsports = rsrc[filter_param['sIP']].sports
            rprotos = rsrc[filter_param['sIP']].protocols
            
            if rdports == [] and rsports == [] and rprotos == []:
                result = False
            
            if str(filter_param['dport']) in rdports:
                result = False
            
            if str(filter_param['sport']) in rsports:
                result = False
            
            for i in filter_param['protocols']:
                if i in rprotos:
                    result = False
                    break
        return result
    
    def sync_start(self):
        self._netfilter_obj = nfqueue.queue()
        self._netfilter_obj.set_callback(self._filter)        
        self._netfilter_obj.fast_open(1, socket.AF_INET)
        self._netfilter_obj.set_queue_maxlen(65535)        
        try:
            self._netfilter_obj.try_run()
        except KeyboardInterrupt:
            print('[!] Exiting')
            print('[!] Unbind NetfilterQueue')
            self._netfilter_obj.unbind(socket.AF_INET)
            print('[!] Close NetfilterQueue')
            self._netfilter_obj.close()
            


    def add_rule(self, ip, dports='', sports='', protocols='', src_or_dst='both'):
        """"""
        assert src_or_dst in ['src', 'dst', 'both'], '[!] Error in param [src_or_dst] ! ' + \
               ' Must be the one of ["src", "dst", "both"]'
        
        def parse_ports(param):
            ports = []
            if param == '':
                return []
            if ',' in param:
                for i in param.split(','):
                    if '-' in i:
                        kv = i.split('-')
                        v0 = int(kv[0].strip())
                        v1 = int(kv[1].strip())
                        ports = ports + map(str, range(v0, v1))
                    else:
                        ports.append(i.strip())
                        
            else:
                ports.append(str(param.strip()))
                
            return ports
        
        if ',' in protocols:
            protocols = map(lambda x: x.strip(), protocols.split(','))
        else:
            if protocols == '':
                protocols = []
            else:
                _ = []
                _.append(protocols)
                protocols = _
        
        
        ret = Rule(IP_addr=ip, 
                   dports=parse_ports(dports),
                   sports=parse_ports(sports),
                   protos=protocols)
        
        if src_or_dst == 'src':
            self._rule_table['src'][ret.ip] = ret
        elif src_or_dst == 'dst':
            self._rule_table['dst'][ret.ip] = ret
        else:
            self._rule_table['src'][ret.ip] = ret
            self._rule_table['dst'][ret.ip] = ret            
        
        
class SmplFWTest(unittest.case.TestCase):
    """"""
    
    def test_singleton(self):
        """"""
        
        self.assertTrue(SmplFireWall() is SmplFireWall())

    def test_running_test(self):
        """"""
        
        s = SmplFireWall()
        #s.add_rule(src_or_dst='dst', ip='192.168.110.255')
        s.add_rule(ip='45.78.6.64', sports='80', dports='80')
        s.add_rule(ip='192.168.110.1', sports='54915')
        #s.add_rule(ip='*')
        s.sync_start()
        s.clearing_nfqueue_bind()

if __name__ == '__main__':
    unittest.main()