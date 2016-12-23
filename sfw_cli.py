#!/usr/bin/env python
#coding:utf-8
"""
  Author:   --<v1ll4n>
  Purpose: G3ar entry
  Created: 2016/12/23
"""

import unittest

import cmd
import shlex
from smplfirewall import SmplFireWall
from argparse import ArgumentParser

class SFWConsole(cmd.Cmd):
    
    def __init__(self, *args, **kwargs):
        cmd.Cmd.__init__(self, *args, **kwargs)
        
        self.prompt = 'SmplFireWall Interacter >> '
    
        self._sfw_instance = None
    
    def do_create(self, arg):
        if arg == '':
            self._sfw_instance = SmplFireWall(HOOK_TABLE='INPUT')
        else:
            self._sfw_instance = SmplFireWall(arg)
    
    def do_add(self, arg):
        param = {}
        try:
            print arg
            parser = ArgumentParser()
            parser.add_argument('IP', metavar='IP')
            parser.add_argument('--sport', dest='sport', default='')
            parser.add_argument('--dport', dest='dport', default='')
            parser.add_argument('--protocols', dest='protocol', default='')
            parser.add_argument('--direct', dest='direct', default='')
            
            options = parser.parse_args(shlex.split(arg))
            param['ip'] = options.IP
            param['sports'] = options.sport
            param['protocols'] = options.protocols
            param['dports'] = options.dport
            param['src_or_dst'] = options.direct
        except:
            pass
        
        if self._sfw_instance:
            self._sfw_instance.add_rule(**param)
    
    def do_start(self, arg):
        if self._sfw_instance:
            self._sfw_instance.sync_start()
        else:
            print '[!] You haven\' t create FireWall instance!'
        
            

if __name__ == '__main__':
    SFWConsole().cmdloop()