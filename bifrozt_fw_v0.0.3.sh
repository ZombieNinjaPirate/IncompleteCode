#!/bin/bash

#
#   Copyright (c) 2014, Are Hansen - Honeypot Development
# 
#   All rights reserved.
# 
#   Redistribution and use in source and binary forms, with or without modification, are
#   permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this list
#   of conditions and the following disclaimer.
# 
#   2. Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or other
#   materials provided with the distribution.
# 
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND AN
#   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#   OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
#   SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
#   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
#   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#   BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
#   STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
#   THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

declare -rx ipt="/sbin/iptables"

# - IP addresses
declare loopback="127.0.0.1/32"
declare multicast="224.0.0.1/32"
declare network="10.199.115.0/24"
declare gateway="10.199.115.1/32"
declare broadcast="10.199.115.255/32"

# - Macros
declare drop_new="-m state --state NEW -m recent --update"
declare state_new="-m state --state NEW -m recent --set -m limit"
declare tcp_frwd="$ipt -A FORWARD -s $network -o eth0 -p tcp -m tcp"
declare udp_frwd="$ipt -A FORWARD -s $network -o eth0 -p udp -m udp"


# ================ FORWARD

function check_numb()
{
    test "$1" && printf '%d' "$1" &>/dev/null
    if [ "$?" != "0" ]
    then
        echo "ERROR: $1 dont appear to be an interger"
    fi
}


function change_dc_ftp()
{
while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' ftp_frame
    case $ftp_frame in
        1)
            ftp_frame="s";
            ftp_time="1";
            break
            ;;
        2)
            ftp_frame="m";
            ftp_time="60";
            break
            ;;
        3)
            ftp_frame="h";
            ftp_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' ftp_pkts
    check_numb $ftp_pkts
    ftp_pkts="$ftp_pkts"
    break
done
}


function change_dc_dns()
{
while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' dns_frame
    case $dns_frame in
        1)
            ftp_frame="s";
            dns_time="1";
            break
            ;;
        2)
            dns_frame="m";
            dns_time="60";
            break
            ;;
        3)
            dns_frame="h";
            dns_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' dns_pkts
    check_numb $dns_pkts
    dns_pkts="$dns_pkts"
    break
done
}


function change_dc_http()
{
while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' http_frame
    case $http_frame in
        1)
            http_frame="s";
            http_time="1";
            break
            ;;
        2)
            http_frame="m";
            http_time="60";
            break
            ;;
        3)
            http_frame="h";
            http_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' http_pkts
    check_numb $http_pkts
    http_pkts="$http_pkts"
    break
done
}


function change_dc_https()
{
while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' https_frame
    case $https_frame in
        1)
            https_frame="s";
            https_time="1";
            break
            ;;
        2)
            https_frame="m";
            https_time="60";
            break
            ;;
        3)
            https_frame="h";
            https_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' https_pkts
    check_numb $https_pkts
    https_pkts="$https_pkts"
    break
done
}


function change_dc_irc()
{
while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' irc_frame
    case $irc_frame in
        1)
            irc_frame="s";
            irc_time="1";
            break
            ;;
        2)
            irc_frame="m";
            irc_time="60";
            break
            ;;
        3)
            irc_frame="h";
            irc_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' irc_pkts
    check_numb $irc_pkts
    irc_pkts="$https_pkts"
    break
done
}


function change_bifrozt_dc()
{
while true
do
    echo ''
    echo 'You are about to change the data control values of the Bifrozt firewall.'
    echo 'If you are uncertain what this is and what the effects of changing these'
    echo 'values are, please exit the script and educate yourself first.'
    echo ''
    echo '      1) FTP          (default: 6 packets/second)'
    echo '      2) DNS          (default: 6 packets/second)'
    echo '      3) HTTP         (default: 6 packets/second)'
    echo '      4) HTTPS        (default: 6 packets/second)'
    echo '      5) IRC          (default: 6 packets/second)'
    echo '      6) TCP other    (default: 15 packets/minute)'
    echo '      7) UDP other    (default: 15 packets/minute)'
    echo ''
    echo '      Q) QUIT'
    echo ''
    read -p 'Select a service: ' service
    case $service in
        1)
            change_dc_ftp
            ;;
        2)
            change_dc_dns
            ;;
        3)
            change_dc_http
            ;;
        4)
            change_dc_https
            ;;
        5)
            change_dc_irc
            ;;
        6)
            change_dc_tcp
            ;;
        7)
            change_dc_udp
            ;;
        Q)
            exit 0 ;
            break
            ;;
        *)
            echo 'Invalid selection [1 - 7].'
            ;;
    esac
done
}

$tcp_frwd --dport 20:21 $state_new --limit $ftp_pkts/$ftp_frame --limit-burst $ftp_pkts -j LOG --log-prefix "BIFROZT - FTP: " --log-level 7
$tcp_frwd --dport 20:21 $drop_new --seconds $ftp_time --hitcount $ftp_pkts -j DROP

$udp_frwd --dport 53 $state_new --limit $dns_pkts/$dns_frame --limit-burst $dns_pkts -j LOG --log-prefix "BIFROZT - DNS udp: " --log-level 7
$udp_frwd --dport 53 $drop_new --seconds $dns_time --hitcount $dns_pkts -j DROP

$tcp_frwd --dport 80 $state_new --limit $http_pkts/$http_frame --limit-burst $http_pkts -j LOG --log-prefix "BIFROZT - HTTP: " --log-level 7
$tcp_frwd --dport 80 $drop_new --seconds $http_time --hitcount $http_pkts -j DROP

$tcp_frwd --dport 443 $state_new --limit 6/sec --limit-burst 6 -j LOG --log-prefix "BIFROZT - HTTPS: " --log-level 7
$tcp_frwd --dport 443 $drop_new --seconds 1 --hitcount 6 -j DROP

$tcp_frwd --dport 6660:6667 $state_new --limit 6/sec --limit-burst 6 -j LOG --log-prefix "BIFROZT - IRC: " --log-level 7
$tcp_frwd --dport 6660:6667 $drop_new --seconds 1 --hitcount 6 -j DROP

$tcp_frwd $state_new --limit 15/min --limit-burst 6 -j LOG --log-prefix "BIFROZT - Data control TCP: " --log-level 7
$tcp_frwd $drop_new --seconds 60 --hitcount 15 -j DROP

$udp_frwd $state_new --limit 15/min --limit-burst 6 -j LOG --log-prefix "BIFROZT - Data control UDP: " --log-level 7
$udp_frwd $drop_new --seconds 60 --hitcount 15 -j DROP
