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
clear

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


function change_dc_telnet()
{
clear

while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' telnet_frame
    case $telnet_frame in
        1)
            telnet_frame="s";
            telnet_time="1";
            break
            ;;
        2)
            telnet_frame="m";
            telnet_time="60";
            break
            ;;
        3)
            telnet_frame="h";
            telnet_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' telnet_pkts
    check_numb $telnet_pkts
    telnet_pkts="$telnet_pkts"
    break
done
}


function change_dc_dns()
{
clear

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
clear

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


function change_dc_popv3()
{
clear

while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' popv3_frame
    case $popv3_frame in
        1)
            popv3_frame="s";
            popv3_time="1";
            break
            ;;
        2)
            popv3_frame="m";
            popv3_time="60";
            break
            ;;
        3)
            popv3_frame="h";
            popv3_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' popv3_pkts
    check_numb $popv3_pkts
    popv3_pkts="$popv3_pkts"
    break
done
}


function change_dc_https()
{
clear

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


function change_dc_smb()
{
clear

while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' smb_frame
    case $smb_frame in
        1)
            smb_frame="s";
            smb_time="1";
            break
            ;;
        2)
            smb_frame="m";
            smb_time="60";
            break
            ;;
        3)
            smb_frame="h";
            smb_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' smb_pkts
    check_numb $smb_pkts
    smb_pkts="$smb_pkts"
    break
done
}


function change_dc_afp()
{
clear

while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' afp_frame
    case $afp_frame in
        1)
            afp_frame="s";
            afp_time="1";
            break
            ;;
        2)
            afp_frame="m";
            afp_time="60";
            break
            ;;
        3)
            afp_frame="h";
            afp_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' afp_pkts
    check_numb $afp_pkts
    irc_pkts="$afp_pkts"
    break
done
}

function change_dc_afp()
{
clear

while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' afp_frame
    case $afp_frame in
        1)
            afp_frame="s";
            afp_time="1";
            break
            ;;
        2)
            afp_frame="m";
            afp_time="60";
            break
            ;;
        3)
            afp_frame="h";
            afp_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' afp_pkts
    check_numb $afp_pkts
    afp_pkts="$afp_pkts"
    break
done
}


function change_dc_smtp()
{
clear

while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' smtp_frame
    case $smtp_frame in
        1)
            smtp_frame="s";
            smtp_time="1";
            break
            ;;
        2)
            smtp_frame="m";
            smtp_time="60";
            break
            ;;
        3)
            smtp_frame="h";
            smtp_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' smtp_pkts
    check_numb $smtp_pkts
    smtp_pkts="$smtp_pkts"
    break
done
}


function change_dc_pop3s()
{
clear

while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' pop3s_frame
    case $pop3s_frame in
        1)
            pop3s_frame="s";
            pop3s_time="1";
            break
            ;;
        2)
            pop3s_frame="m";
            pop3s_time="60";
            break
            ;;
        3)
            pop3s_frame="h";
            pop3s_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' pop3s_pkts
    check_numb $pop3s_pkts
    pop3s_pkts="$pop3s_pkts"
    break
done
}


function change_dc_mssql()
{
clear

while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' mssql_frame
    case $mssql_frame in
        1)
            mssql_frame="s";
            mssql_time="1";
            break
            ;;
        2)
            mssql_frame="m";
            mssql_time="60";
            break
            ;;
        3)
            mssql_frame="h";
            mssql_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' mssql_pkts
    check_numb $mssql_pkts
    mssql_pkts="$mssql_pkts"
    break
done
}


function change_dc_mysql()
{
clear

while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' mysql_frame
    case $mysql_frame in
        1)
            mysql_frame="s";
            mysql_time="1";
            break
            ;;
        2)
            mysql_frame="m";
            mysql_time="60";
            break
            ;;
        3)
            mysql_frame="h";
            mysql_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' mysql_pkts
    check_numb $mysql_pkts
    mysql_pkts="$mysql_pkts"
    break
done
}


function change_dc_irc()
{
clear

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
    irc_pkts="$irc_pkts"
    break
done
}


function change_dc_httpalt()
{
clear

while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' httpalt_frame
    case $httpalt_frame in
        1)
            httpalt_frame="s";
            httpalt_time="1";
            break
            ;;
        2)
            httpalt_frame="m";
            httpalt_time="60";
            break
            ;;
        3)
            httpalt_frame="h";
            httpalt_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' httpalt_pkts
    check_numb $httpalt_pkts
    httpalt_pkts="$httpalt_pkts"
    break
done
}


function change_dc_tcp()
{
clear

while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' tcp_frame
    case $tcp_frame in
        1)
            tcp_frame="s";
            tcp_time="1";
            break
            ;;
        2)
            tcp_frame="m";
            tcp_time="60";
            break
            ;;
        3)
            tcp_frame="h";
            tcp_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' tcp_pkts
    check_numb $tcp_pkts
    tcp_pkts="$tcp_pkts"
    break
done
}


function change_dc_tcp()
{
clear

while true
do
    echo ''
    echo 'Choose new time frame'
    echo ''
    echo '      1) Second'
    echo '      2) Minute'
    echo '      3) Hour'
    echo ''
    read -p 'Enter your selection: ' udp_frame
    case $udp_frame in
        1)
            udp_frame="s";
            udp_time="1";
            break
            ;;
        2)
            udp_frame="m";
            udp_time="60";
            break
            ;;
        3)
            udp_frame="h";
            udp_time="3600";
            break
            ;;
        *)
            echo 'Please enter a valid selection (1, 2 or 3)'
            ;;
    esac
done

while true
do
    read -p 'Number of packets within that time frae: ' udp_pkts
    check_numb $udp_pkts
    udp_pkts="$udp_pkts"
    break
done
}


function change_bifrozt_dc()
{
clear

ftp_pkts="6"
ftp_frame="s"
ftp_time="1"

telnet_pkts="6"
telnet_frame="s"
telnet_time="1"

dns_pkts="6"
dns_frame="s"
dns_time="1"

http_pkts="6"
http_frame="s"
http_time="1"

popv3__pkts="6"
popv3_frame="s"
popv3_time="1"

https_pkts="6"
https_frame="s"
https_time="1"

smb_pkts="6"
smb_frame="s"
smb_time="1"

afp_pkts="6"
afp_frame="s"
afp_time="1"

smtp_pkts="6"
smtp_frame="s"
smtp_time="1"

pop3s_pkts="6"
pop3s_frame="s"
pop3s_time="1"

mssql_pkts="6"
mssql_frame="s"
mssql_time="1"

mysql_pkts="6"
mysql_frame="s"
mysql_time="1"

irc_pkts="6"
irc_frame="s"
irc_time="1"

tcp_pkts="15"
tcp_frame="m"
tcp_time="60"

udp_pkts="15"
udp_pkts="m"
udp_time="60"

while true
do
    echo ''
    echo 'You are about to change the data control values of the Bifrozt firewall.'
    echo 'If you are uncertain what this is and what the effects of changing these'
    echo 'values are, please exit the script and educate yourself first.'
    echo ''
    echo ''
    echo '         Service          Port                 Default'
    echo '  ---------------------------------------------------------'
    echo ''
    echo '   1)     FTP             tcp/20:21             6/sec'
    echo '   2)     TELNET          tcp/23                6/sec'
    echo '   3)     DNS             udp/53                6/sec'
    echo '   4)     HTTP            tcp/80                6/sec'
    echo '   5)     POPv3           tcp/110               6/sec'
    echo '   6)     HTTPS           tcp/443               6/sec'
    echo '   7)     SMB             tcp/445               6/sec'
    echo '   8)     AFP             tcp/548               6/sec'
    echo '   9)     SMTP            tcp/587               6/sec'
    echo '  10)     POP3S           tcp/995               6/sec'
    echo '  11)     MSSQL           tcp/1433              6/sec'
    echo '  12)     MYSQL           tcp/3306              6/sec'
    echo '  13)     IRC             tcp/6660:6669         6/sec'
    echo '  14)     HTTP-Alt        tcp/8080:8081         6/sec'
    echo '  15)     TCP             All other TCP        15/min'
    echo '  16)     UDP             All other UDP        15/min'
    echo ''
    echo '  ---------------------------------------------------------'
    echo ''
    echo '  D) DONE'
    echo '  Q) QUIT'
    echo ''
    read -p 'Select a service: ' service
    case $service in
        1)
            change_dc_ftp
            ;;
        2)
            change_dc_telnet
            ;;
        3)
            change_dc_dns
            ;;
        4)
            change_dc_http
            ;;
        5)
            change_dc_popv3
            ;;
        6)
            change_dc_https
            ;;
        7)
            change_dc_smb
            ;;
        8)
            change_dc_afp
            ;;
        9)
            change_dc_smtp
            ;;
        10)
            change_dc_pop3s
            ;;
        11)
            change_dc_mssql
            ;;
        12)
            change_dc_mysql
            ;;
        13)
            change_dc_irc
            ;;
        14)
            change_dc_httpalt
            ;;
        15)
            change_dc_tcp
            ;;
        16)
            change_dc_udp
            ;;
        D)
            make_rules;
            break
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


function make_rules()
{
cat << _EOF_
$tcp_frwd --dport 20:21 $state_new --limit $ftp_pkts/$ftp_frame --limit-burst $ftp_pkts -j LOG --log-prefix "BIFROZT - FTP: " --log-level 7
$tcp_frwd --dport 20:21 $drop_new --seconds $ftp_time --hitcount $ftp_pkts -j DROP

$tcp_frwd --dport 23 $state_new --limit $telnet_pkts/$telnet_frame --limit-burst $telnet_pkts -j LOG --log-prefix "BIFROZT - TELNET: " --log-level 7
$tcp_frwd --dport 23 $drop_new --seconds $telnet_time --hitcount $telnet_pkts -j DROP

$udp_frwd --dport 53 $state_new --limit $dns_pkts/$dns_frame --limit-burst $dns_pkts -j LOG --log-prefix "BIFROZT - DNS udp: " --log-level 7
$udp_frwd --dport 53 $drop_new --seconds $dns_time --hitcount $dns_pkts -j DROP

$tcp_frwd --dport 80 $state_new --limit $http_pkts/$http_frame --limit-burst $http_pkts -j LOG --log-prefix "BIFROZT - HTTP: " --log-level 7
$tcp_frwd --dport 80 $drop_new --seconds $http_time --hitcount $http_pkts -j DROP

$tcp_frwd --dport 110 $state_new --limit $popv3_pkts/$popv3_frame --limit-burst $popv3_pkts -j LOG --log-prefix "BIFROZT - POPv3: " --log-level 7
$tcp_frwd --dport 110 $drop_new --seconds $popv3_time --hitcount $popv3_pkts -j DROP

$tcp_frwd --dport 443 $state_new --limit $https_pkts/$https_frame --limit-burst $https_pkts -j LOG --log-prefix "BIFROZT - HTTPS: " --log-level 7
$tcp_frwd --dport 443 $drop_new --seconds $https_time --hitcount $https_pkts -j DROP

$tcp_frwd --dport 445 $state_new --limit $smb_pkts/$smb_frame --limit-burst $smb_pkts -j LOG --log-prefix "BIFROZT - SMB: " --log-level 7
$tcp_frwd --dport 445 $drop_new --seconds $smb_time --hitcount $smb_pkts -j DROP

$tcp_frwd --dport 548 $state_new --limit $afp_pkts/$afp_frame --limit-burst $smb_pkts -j LOG --log-prefix "BIFROZT - AFP: " --log-level 7
$tcp_frwd --dport 548 $drop_new --seconds $afp_time --hitcount $afp_pkts -j DROP

$tcp_frwd --dport 587 $state_new --limit $smtp_pkts/$smtp_frame --limit-burst $smtp_pkts -j LOG --log-prefix "BIFROZT - SMTP: " --log-level 7
$tcp_frwd --dport 587 $drop_new --seconds $smtp_time --hitcount $smtp_pkts -j DROP

$tcp_frwd --dport 995 $state_new --limit $pop3s_pkts/$pop3s_frame --limit-burst $pop3s_pkts -j LOG --log-prefix "BIFROZT - POP3S: " --log-level 7
$tcp_frwd --dport 995 $drop_new --seconds $pop3s_time --hitcount $pop3s_pkts -j DROP

$tcp_frwd --dport 1433 $state_new --limit $mssql_pkts/$mssql_frame --limit-burst $mssql_pkts -j LOG --log-prefix "BIFROZT - MSSQL: " --log-level 7
$tcp_frwd --dport 1433 $drop_new --seconds $mssql_time --hitcount $mssql_pkts -j DROP

$tcp_frwd --dport 3306 $state_new --limit $mysql_pkts/$mysql_frame --limit-burst $mysql_pkts -j LOG --log-prefix "BIFROZT - MYSQL: " --log-level 7
$tcp_frwd --dport 3306 $drop_new --seconds $mysql_time --hitcount $mysql_pkts -j DROP

$tcp_frwd --dport 6660:6667 $state_new --limit $irc_pkts/$irc_frame --limit-burst $irc_pkts -j LOG --log-prefix "BIFROZT - IRC: " --log-level 7
$tcp_frwd --dport 6660:6667 $drop_new --seconds $irc_pkts --hitcount $irc_pkts -j DROP

$tcp_frwd --dport 8080:8081 $state_new --limit $httpalt_pkts/$httpalt_frame --limit-burst $httpalt_pkts -j LOG --log-prefix "BIFROZT - HTTP-Alt: " --log-level 7
$tcp_frwd --dport 8080:8081 $drop_new --seconds $httpalt_pkts --hitcount $httpalt_pkts -j DROP

$tcp_frwd $state_new --limit $tcp_pkts/$tcp_frame --limit-burst $tcp_pkts -j LOG --log-prefix "BIFROZT - Data control TCP: " --log-level 7
$tcp_frwd $drop_new --seconds $tcp_time --hitcount $tcp_pkts -j DROP

$udp_frwd $state_new --limit $udp_pkts/$udp_frame --limit-burst $udp_pkts -j LOG --log-prefix "BIFROZT - Data control UDP: " --log-level 7
$udp_frwd $drop_new --seconds $udp_time --hitcount $udp_pkts -j DROP
_EOF_
}


change_bifrozt_dc

exit 0

