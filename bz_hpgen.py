#!/usr/bin/env bash

# ------------------------------- The Bifrozt Honeypot Project 2014 ------------------------------- #
#
#
#  Copyright (c) 2014, Are Hansen - Honeypot Development.
#
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without modification, are permitted
#  provided that the following conditions are met:
#
#  1. Redistributions of source code must retain the above copyright notice, this list of conditions
#  and the following disclaimer.
#
#  2. Redistributions in binary form must reproduce the above copyright notice, this list of
#  conditions and the following disclaimer in the documentation and/or other materials provided with
#  the distribution.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND AN EXPRESS OR
#  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
#  FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
#  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  WHETHERIN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
#  WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
# ------------------------------- The Bifrozt Honeypot Project 2014 ------------------------------- #


__author__ = 'Are Hansen'
__date__ = '2014, May 21'
__version__ = '0.0.1'


import argparse
import os
import sys


def parse_args():
    """
    Defines the command line arguments.
    """
    hlog = '/opt/honssh/logs'

    parser = argparse.ArgumentParser('Generate basic honeyd.conf')

    client = parser.add_argument_group('- Honeypot configuration')
    client.add_argument('-O', dest='ostype', help='OS type', required=True,
                        choices=['win', 'nix', 'osx'])
    client.add_argument('-U', dest='uptime', help='Average uptime', type=int, required=True)
    client.add_argument('-M', dest='macadd', help='MAC address vendor', type=str, required=True,
                        choices=['Apple', 'Dell', 'D-Link', 'Lenovo', 'Netgear', 'Panasonic'])
    client.add_argument('-n', dest='volume', help='Number of honeypots to create', required=True)

    args = parser.parse_args()

    return args


#
# --- MAC address vendor ---
#
mac_apple = ['80:ea:96', '68:5b:35', '58:b0:35', '58:55:ca', '54:e4:3a',
             '14:10:9f', '10:dd:b1', '10:9a:dd', 'f8:1e:df', 'c8:2a:14']
mac_delli = ['a4:ba:db', '00:b0:d0', '00:c0:4f', '00:06:5b', '00:08:74',
             '00:b0:d0', 'd4:ae:52', 'd4:be:d9', 'f0:4d:a2', '5c:f9:dd']
mac_dlink = ['00:05:5d', '00:0d:88', '00:0f:3d', '00:80:c8', '14:d6:4d',
             '1c:7e:e5', '1c:af:f7', '34:08:04', '78:54:2e', '90:94:e4']
mac_lenov = ['00:06:1b', 'ec:89:f5', 'd8:71:57', 'd4:22:3f', 'c8:dd:c9',
             '80:cf:41', '50:3c:c4', '14:9f:e8', '00:59:07', '00:12:fe']
mac_netgr = ['00:09:5b', '00:0f:b5', '00:14:6c', 'e0:91:f5', 'e0:46:9a',
             'c4:3d:c7', 'c0:3f:0e', 'a0:21:b7', '84:1b:5e', '74:44:01']
mac_panas = ['d8:b1:2a', 'd8:af:f1', 'cc:7e:e7', '8c:c1:21', '70:58:12',
             '30:4c:7e', '00:d0:60', '00:c0:8f', '00:1b:d3', '00:0f:12']


def make_honeyd(hpos, utime, mac, numb):

    if hpos == 'win':
        for i in range(int(numb)):
            print 'create win{0}'.format(i)
            print 'set win{0} personality "Microsoft Windows XP Professional SP1"'.format(i)
            print 'set win{0} default tcp action reset'.format(i)
            print 'set win{0} uptime {1}'.format(i, utime)
            print 'set win{0} droprate in 1'.format(i)
            print 'add win{0} tcp port 135 open'.format(i)
            print 'add win{0} tcp port 139 open'.format(i)
            print 'add win{0} tcp port 445 open'.format(i)
            print 'set win{0} ethernet "00:06:1b:ea:18:4e"'.format(i)
            print 'bind 10.199.115.7 win{0}'.format(i)
            print ''


def process_args(args):
    """Process the command line arguments. """

    make_honeyd(args.ostype, args.uptime, args.macadd, args.volume)

def main():
    """Do what Main does best..."""
    args = parse_args()
    process_args(args)


if __name__ == '__main__':
    main()
