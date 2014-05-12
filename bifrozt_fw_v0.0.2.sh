#!/bin/bash

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
    else
        break
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
    case $FTP_FRAME in
        1)
            ftp_frame="s";
            break
            ;;
        2)
            ftp_frame="m";
            break
            ;;
        3)
            ftp_frame="h";
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

cat << _xXx_
$tcp_frwd --dport 20:21 $state_new --limit $PKTS/$FTP_FRAME --limit-burst $PKTS -j LOG --log-prefix "BIFROZT - FTP: " --log-level 7
$tcp_frwd --dport 20:21 $drop_new --seconds $ftp_time --hitcount $ftp_pkts -j DROP
_xXx_
#
#$udp_frwd --dport 53 $state_new --limit 12/sec --limit-burst 12 -j LOG --log-prefix "BIFROZT - DNS udp: " --log-level 7
#$udp_frwd --dport 53 $drop_new --seconds 1 --hitcount 12 -j DROP
#
#$tcp_frwd --dport 80 $state_new --limit 6/sec --limit-burst 6 -j LOG --log-prefix "BIFROZT - HTTP: " --log-level 7
#$tcp_frwd --dport 80 $drop_new --seconds 1 --hitcount 6 -j DROP
#
#$tcp_frwd --dport 443 $state_new --limit 6/sec --limit-burst 6 -j LOG --log-prefix "BIFROZT - HTTPS: " --log-level 7
#$tcp_frwd --dport 443 $drop_new --seconds 1 --hitcount 6 -j DROP
#
#$tcp_frwd --dport 6660:6667 $state_new --limit 6/sec --limit-burst 6 -j LOG --log-prefix "BIFROZT - IRC: " --log-level 7
#$tcp_frwd --dport 6660:6667 $drop_new --seconds 1 --hitcount 6 -j DROP
#
#$tcp_frwd $state_new --limit 15/min --limit-burst 6 -j LOG --log-prefix "BIFROZT - Data control TCP: " --log-level 7
#$tcp_frwd $drop_new --seconds 60 --hitcount 15 -j DROP
#
#$udp_frwd $state_new --limit 15/min --limit-burst 6 -j LOG --log-prefix "BIFROZT - Data control UDP: " --log-level 7
#$udp_frwd $drop_new --seconds 60 --hitcount 15 -j DROP
#
