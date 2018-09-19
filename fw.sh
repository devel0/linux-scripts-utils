#!/bin/bash

# [os install notes](https://github.com/devel0/knowledge/blob/master/linux/quick-and-dirty-server-install-notes.md)

#-------
# debug
#-------
#set -x

source /etc/environment

#
# !!! TODO: set to false
#
ACCEPTALL=false
ACCEPTOUTFWD=false

#
#
#
# CONSTANTS
#
#############################################################################

	# core containers ( 172.18.0.0/16 )

	ip_dns_fw='172.18.0.1'
	ip_dns_srv='172.18.0.2'

	# security manager ( 172.18.0.4/16 )

	ip_sec_srv='172.18.0.6'

	# system containers ( 172.19.0.0/16 )

	ip_nginx_gw='172.19.0.1'
	ip_nginx_srv='172.19.0.2'

        ip_doc_gw='172.19.0.5'
        ip_doc_srv='172.19.0.6'

        ip_dc01_gw='172.19.0.9'
        ip_dc01_srv='172.19.0.10'
	ip_dc01_bcast='172.19.0.11'

	ip_cloud_psql_gw='172.19.0.17'
	ip_cloud_psql_srv='172.19.0.18'

	ip_cloud_gw='172.19.0.21'
	ip_cloud_srv='172.19.0.22'

	ip_zimbra_gw='172.19.0.25'
	ip_zimbra_srv='172.19.0.26'

	ip_cloud_sync_gw='172.19.0.29'
	ip_cloud_sync_srv='172.19.0.30'

	ip_imapsync_gw='172.19.0.33'
	ip_imapsync_srv='172.19.0.34'

	# build network ( 172.20.0.0/16 )

	#=============================
	# INTERNET and SPECIAL IPs
	#===========================

	if_wan=enp3s0
	if_lan=br0

	ip_my_public='xxx.yyy.zzz.www'
	ip_sat='www.xxx.ttt.xxx' # insert itadmin ip address here to enable ssh from remote only to their ip

	ip_gw='192.168.1.1'
	ip_wan='192.168.1.254'
	ip_my='192.168.10.200' # dc
	ip_my1='192.168.10.201' # nas
	ip_my_alt='192.168.9.200'
	bcast_my='192.168.10.255'

	ip_switch='192.168.10.254'

	ip_google_dns1='8.8.8.8'
	ip_google_dns2='8.8.4.4'

	ip_lo='127.0.0.1'
	ip_multicast='255.255.255.255'
	ip_multicast_ping='224.0.0.1'
	ip_llmnr='224.0.0.252'

	#============
	# INTERFACES
	#============

	if_lo="lo"

	# dns

	if_dns=$(dk-if dns)

	# security manager

	if_sec=$(dk-if sec)

	# system

	if_nginx=$(dk-if nginx)
	if_doc=$(dk-if doc)
	if_dc01=$(dk-if dc01)
	if_nas=$(dk-if nas)
	if_cloud_psql=$(dk-if cloud_psql)
	if_cloud_sync=$(dk-if cloud_sync)
	if_cloud=$(dk-if cloud)
	if_zimbra=$(dk-if zimbra)
	if_imapsync=$(dk-if imapsync)

	# build

	if_build=$(dk-if build)

	#==========
	# NETWORKS
	#==========

	net_lan='192.168.10.0/24'

	# system

	net_dns='172.18.0.0/30'
	net_sec='172.18.0.4/30'

	# apps

	net_nginx='172.19.0.0/30'
	net_doc='172.19.0.4/30'
	net_dc01='172.19.0.8/30'
	net_nas='172.19.0.12/30'
	net_cloud_psql='172.19.0.16/30'
	net_cloud='172.19.0.20/30'
	net_zimbra='172.19.0.24/30'
	net_cloud_sync='172.19.0.30/30'
	net_imapsync='172.19.0.34/30'

	# build

        net_build='172.20.0.0/16'

	# general

	iana_ephemeral_from=49152
	iana_ephemeral_to=65535

	net_priv_a='10.0.0.0/8'
	net_priv_b='172.16.0.0/12'
	net_priv_c='192.168.0.0/16'
	net_priv_d='224.0.0.0/4'
	net_priv_e='240.0.0.0/5'

	net_lo='127.0.0.1/8'

	net_dockers=$net_priv_b
	net_privs=$net_priv_a,$net_priv_b,$net_priv_c,$net_priv_d,$net_priv_e,$net_lo
	net_lan_and_dockers=$net_lan,$net_dockers

	#==========
	# SERVICES
	#==========

	# Active Directory Replication over Firewalls ( https://technet.microsoft.com/en-us/library/bb727063.aspx )

	svc_ftp_data='20'
	svc_ftp='21'
	svc_ssh='22'
	svc_telnet='23'
	svc_smtp='25'
	svc_winsrep='42'
	svc_dns='53'
	svc_bootps='67'
	svc_bootpc='68'
	svc_tftp='69'
	svc_http='80'
	svc_krb='88'
	svc_ntp='123'
	svc_rpcepmap='135'
	svc_netbios_ns='137'
	svc_netbios_dgm='138'
	svc_netbios_ssn='139'
	svc_ldap='389'
	svc_https='443'
	svc_samba='445'
	svc_krbpwd='464'
	svc_smtps='465'
	svc_submission='587'
	svc_ldaps='636'
	svc_imaps='993'
	svc_ovpn='1194'
	svc_wins='1512'
	svc_hasp='1947'
	svc_ntopng='3000'
	svc_proxy='3128'
	svc_gcat='3268'
	svc_gcat_ssl='3269'
	svc_rdp='3389'
	svc_webapi_5000='5000'
	svc_iperf='5201'
	svc_iperfs='5201:5210'
	svc_psql='5432'
	svc_hostmon='5355'
	svc_git='9418'
	svc_hkp='11371'
	svc_mongo='27017'
	svc_rpcdyn='1024:65535'
	svc_alt10='50010'

	svc_samba_all=$svc_netbios_ns,$svc_netbios_dgm,$svc_netbios_ssn,$svc_samba

	#=======================
	# general allowed zones
	#=======================

	if [ "$1" == "--only-constants" ]; then return; fi

	echo "fw"

#
#
#
# FIREWALL POLICIES & CERT RENEWAL
#
#############################################################################

	iptprocs=$(pidof iptables)
	if [ "x$iptprocs" != "x" ]; then
		echo "There are other processes using iptables at the moment:"
		echo "$iptprocs = `ps -fp $iptprocs`"
		exit 1
	fi

	#=====
	# LOG
	#=====

	# log dropped packets if policy=DROP
	log_input="true"
	log_forward="true"
	log_output="true"

	#=====
	# CERT RENEWAL [ not used in sws-fs01 ]
	#=====

	# enable follow when need to run /nas/security/ssl-certificate/renew.sh
	if [ "$1" == "--renew-cert" ]; then
		echo "RENEW CERT MODE"
		export cert_renew_mode="true"
	fi

	#=======
	# DEBUG
	#=======

	# warning: log many packets if enabled debug
	debug_input="false"
	debug_forward="false"
	debug_output="false"

	#==================
	# DEFAULT POLICIES
	#==================

	policy_input="DROP"
	policy_output="DROP"
	policy_forward="DROP"

	if $ACCEPTALL; then
		policy_input="ACCEPT"
		policy_output="ACCEPT"
		policy_forward="ACCEPT"
	fi

	if $ACCEPTOUTFWD; then
		policy_output="ACCEPT"
		policy_forward="ACCEPT"
	fi

	#=================
	# COMMAND ALIASES
	#=================

	cmd_ip="/sbin/ip"
	cmd_ipt="/sbin/iptables -w 60"
	cmd_sysctl="/sbin/sysctl -w"
	cmd_ipset="/usr/sbin/ipset"

#
#
#
# FUNCTIONS
#
#############################################################################

	comment=""

	load_modules()
	{
		modprobe ip_conntrack_ftp
	}

	#-------------------------
	# args: [ipset_tbl_name]*
	create_ipset_tables()
	#-------------------------
	{
		for i in $*; do
			echo Creating ipset table [$i]
			$cmd_ipset -N $i nethash >& /dev/null
		done
	}

	#----------------
	reset_iptables()
	#----------------
	{
		echo Resetting iptables

		# check if tables previously exists
		iptables -L -n | grep OUTPUT-2 >&/dev/null

		if [ "$?" == "0" ]; then
			echo "--> FIREWALL MODIFICATION"

			# delete jump to chain
			$cmd_ipt -t filter -D INPUT -j BADPACKETS
			$cmd_ipt -t filter -D INPUT -j INPUT-2
			$cmd_ipt -t filter -D FORWARD -j FORWARD-2
			$cmd_ipt -t filter -D OUTPUT -j OUTPUT-2
			$cmd_ipt -t nat -D PREROUTING -j PREROUTING-2
			$cmd_ipt -t nat -D POSTROUTING -j POSTROUTING-2
			$cmd_ipt -t nat -D OUTPUT -j NAT-OUTPUT-2

			# flush rules
			$cmd_ipt -t filter -F BADPACKETS
			$cmd_ipt -t filter -F INPUT-2
			$cmd_ipt -t filter -F FORWARD-2
			$cmd_ipt -t filter -F OUTPUT-2
			$cmd_ipt -t nat -F PREROUTING-2
			$cmd_ipt -t nat -F POSTROUTING-2
			$cmd_ipt -t nat -F NAT-OUTPUT-2

			# delete chain
			$cmd_ipt -t filter -X BADPACKETS
			$cmd_ipt -t filter -X INPUT-2
			$cmd_ipt -t filter -X FORWARD-2
			$cmd_ipt -t filter -X OUTPUT-2
			$cmd_ipt -t nat -X PREROUTING-2
			$cmd_ipt -t nat -X POSTROUTING-2
			$cmd_ipt -t nat -X NAT-OUTPUT-2

		else
			echo "--> INITIAL FIREWALL"
		fi

		# create chains
		$cmd_ipt -t filter -N BADPACKETS
		$cmd_ipt -t filter -N INPUT-2
		$cmd_ipt -t filter -N FORWARD-2
		$cmd_ipt -t filter -N OUTPUT-2
		$cmd_ipt -t nat -N PREROUTING-2
		$cmd_ipt -t nat -N POSTROUTING-2
		$cmd_ipt -t nat -N NAT-OUTPUT-2

		# create jump to chain
		$cmd_ipt -t filter -A INPUT -j BADPACKETS
		$cmd_ipt -t filter -A INPUT -j INPUT-2
		$cmd_ipt -t filter -A FORWARD -j FORWARD-2
		$cmd_ipt -t filter -A OUTPUT -j OUTPUT-2
		$cmd_ipt -t nat -A PREROUTING -j PREROUTING-2
		$cmd_ipt -t nat -A POSTROUTING -j POSTROUTING-2
		$cmd_ipt -t nat -A OUTPUT -j NAT-OUTPUT-2
	}

	#-----------------------
	setup_network_devices()
	#-----------------------
	{
		echo Setup network devices

		$cmd_ip link set $if_lan up
		$cmd_ip addr add $net_fw broadcast + dev $if_lan >& /dev/null
		if [ "x$GATEWAY_IP" != "x" ]; then
			$cmd_ip route add default via $ip_gw dev $if_inet >& /dev/null
		fi
	}

	#-------------------------------
	setup_kernel_level_protection()
	#-------------------------------
	{
		echo Setup kernel level protection

		# enable SYN flood protection
		$cmd_sysctl net.ipv4.tcp_syncookies="1" >& /dev/null

		# enable reverse path filter
		$cmd_sysctl net.ipv4.conf.all.rp_filter="1" >& /dev/null

		# protect about smurfs attack
		$cmd_sysctl net.ipv4.icmp_echo_ignore_broadcasts="1" >& /dev/null

		# disable icmp redirects
		$cmd_sysctl net.ipv4.conf.all.accept_redirects="0" >& /dev/null

		# allow secure icmp redirects
		$cmd_sysctl net.ipv4.conf.all.secure_redirects="1" >& /dev/null
	}

	#-----------------------
	set_iptables_policies()
	#-----------------------
	{
		echo Setting iptable default policies

		$cmd_ipt -P INPUT $policy_input
		$cmd_ipt -P OUTPUT $policy_output
		$cmd_ipt -P FORWARD $policy_forward
	}

	#.....
	# arg : <table> <log name>
	log()
	#.....
	{
		$cmd_ipt -A $1 ${@:3} -j LOG --log-level info --log-prefix "${2} "
	}

	#..............
	# args: <table> [<iptable-args>]*
	accept()
	#..............
	{
		if [ "x$comment" != "x" ]; then
			$cmd_ipt -A $1 ${@:2} -m comment --comment "$comment" -j ACCEPT
			comment=""
		else
			$cmd_ipt -A $1 ${@:2} -j ACCEPT
		fi
	}

	#......
	# args: <table> [<iptable-args>]*
	drop()
	#......
	{
		if [ "$comment" != "" ]; then
			$cmd_ipt -A $1 -m comment --comment "$comment" ${@:2} -j DROP
			comment=""
		else
			$cmd_ipt -A $1 ${@:2} -j DROP
		fi
	}

	#....................
	# args: <table> [<iptable-args>]*
	accept_established()
	#....................
	{
		accept $1 ${@:2} -m state --state ESTABLISHED,RELATED
	}

	#......
	# args: <table> <chain-to-jump-to> [<iptable-args>]*
	jump()
	#......
	{
		$cmd_ipt -A $1 ${@:3} -j $2
	}

	#.........
	# args: [<iptable-args>]*
	pre_add()
	#.........
	{
		if [ "x$comment" != "x" ]; then
			$cmd_ipt -t nat -A PREROUTING-2 -m comment --comment "$comment" $*
			comment=""
		else
			$cmd_ipt -t nat -A PREROUTING-2 $*
		fi
	}

	#.........
	# args: [<iptable-args>]*
	post_add()
	#.........
	{
		if [ "x$comment" != "x" ]; then
			$cmd_ipt -t nat -A POSTROUTING-2 -m comment --comment "$comment" $*
			comment=""
		else
			$cmd_ipt -t nat -A POSTROUTING-2 $*
		fi
	}

	#.........
	# args: [<iptable-args>]*
	out_add()
	#.........
	{
		if [ "x$comment" != "x" ]; then
			$cmd_ipt -t nat -A NAT-OUTPUT-2 -m comment --comment "$comment" $*
			comment=""
		else
			$cmd_ipt -t nat -A NAT-OUTPUT-2 $*
		fi
	}

	#-------------------
	enable_ip_forward()
	#-------------------
	{
		# enable ip forward
		$cmd_sysctl net.ipv4.ip_forward="1" >&/dev/null
	}

#
#
#
# BAD PACKETS
#
#############################################################################
	#------------------------
	setup_badpackets()
	#------------------------
	{
                echo Setup INPUT chain [base]

                let dropidx=0
                mydrop()
                {
                        if [[ "$policy_input" == "DROP" && "$log_badpackets" == "true" ]]; then
                                log_and_drop $1 "DROP [bad idx=$dropidx]" ${@:2}
                                let dropidx=$dropidx+1
                        else
                                drop $*
                        fi
                }

                # check if bad packets coming from internet
                comment="antispoof my ip pub"
                mydrop BADPACKETS -p ALL -i $if_inet -s $ip_my_public

                comment="antispoof net priv a"
                mydrop BADPACKETS -p ALL -i $if_inet -s $net_priv_a

                comment="antispoof net priv b"
                mydrop BADPACKETS -p ALL -i $if_inet -s $net_priv_b

                comment="antispoof net priv c"
                mydrop BADPACKETS -p ALL -i $if_inet -s $net_priv_c

                comment="antispoof net priv d"
                mydrop BADPACKETS -p ALL -i $if_inet -s $net_priv_d

                comment="antispoof net priv e"
                mydrop BADPACKETS -p ALL -i $if_inet -s $net_priv_e

                comment="antispoof broadcast"
                mydrop BADPACKETS -p ALL -i $if_inet -s 10.255.255.255

                comment="antispoof"
                mydrop BADPACKETS -p ALL -i $if_inet -m state --state INVALID

                comment="antispoof"
                mydrop BADPACKETS -p tcp -i $if_inet ! --syn -m state --state NEW

                comment="antispoof"
                mydrop BADPACKETS -p tcp -i $if_inet --tcp-flags ALL NONE

                comment="antispoof"
                mydrop BADPACKETS -p tcp -i $if_inet --tcp-flags ALL ALL

                comment="antispoof"
                mydrop BADPACKETS -p tcp -i $if_inet --tcp-flags ALL FIN,URG,PSH

                comment="antispoof"
                mydrop BADPACKETS -p tcp -i $if_inet --tcp-flags SYN,RST SYN,RST

                comment="antispoof"
                mydrop BADPACKETS -p tcp -i $if_inet --tcp-flags SYN,FIN SYN,FIN

                comment="antispoof"
                mydrop BADPACKETS -p ICMP -i $if_inet --fragment

                comment="antispoof"
                mydrop BADPACKETS -p UDP -i $if_inet -s 0/0 --destination-port 137

                comment="antispoof"
                mydrop BADPACKETS -p UDP -i $if_inet -s 0/0 --destination-port 138

                comment="antispoof"
                mydrop BADPACKETS -i $if_inet -m pkttype --pkt-type broadcast
	}

#
#
#
# PREROUTING
#
#############################################################################
	setup_prerouting()
	#------------------
	{
		echo Setup PREROUTING and NAT-OUTPUT

		if [ "$cert_renew_mode" != "true" ]; then
			comment="redirect WAN http(s),7071 to nginx docker"
			pre_add -i $if_wan -d $ip_wan -p tcp -m multiport --dports $svc_http,$svc_https,7071 -j DNAT --to $ip_nginx_srv

			comment="redirect lan http(s),7071 to nginx docker"
			pre_add -i $if_lan -d $ip_my -p tcp -m multiport --dports $svc_http,$svc_https,7071 -j DNAT --to $ip_nginx_srv

		else
			echo "---> CERT RENEW MODE"
		fi

		#----------------
		# adjust docker lan addressing
		#----------------

		comment="redirect doc to nginx"
		pre_add -i $if_lan -d $ip_doc_srv -j DNAT --to $ip_nginx_srv

		comment="redirect cloud to nginx"
		pre_add -i $if_lan -d $ip_cloud_srv -j DNAT --to $ip_nginx_srv

		comment="redirect http(s),7071 zimbra to nginx"
		pre_add -i $if_lan -d $ip_zimbra_srv -p tcp -m multiport --dports $svc_http,$svc_https,7071 -j DNAT --to $ip_nginx_srv

		comment="redirect http(s) cloud_sync to cloud to nginx"
		pre_add -i $if_cloud_sync -o $if_cloud -s $ip_cloud_sync_srv -d $ip_cloud_srv -p tcp -m multiport --dports $svc_http,$svc_https -j DNAT --to $ip_nginx_srv

		#-------------------------------
                # domain controller
                #-------------------------------

                comment="redirect lan to dc (udp)"
                pre_add -i $if_lan -s $net_lan -d $ip_my -p udp -m multiport --dports \
			$svc_krb,$svc_netbios_ns,$svc_netbios_dgm,$svc_ldap,$svc_krbpwd,$svc_ntp \
			-j DNAT --to $ip_dc01_srv

                comment="redirect lan to dc (tcp)"
                pre_add -i $if_lan -s $net_lan -d $ip_my -p tcp -m multiport --dports \
			$svc_krb,$svc_rpcepmap,$svc_netbios_ssn,$svc_ldap,$svc_samba,$svc_krbpwd,$svc_ldaps,$svc_gcat,$svc_gcat_ssl,"$iana_ephemeral_from:$iana_ephemeral_to" \
			-j DNAT --to $ip_dc01_srv

		#------------
                # cloud_sync
                #------------

                comment="lan cloud sync rdp"
                pre_add -i $if_lan -d $ip_my -p tcp --dport $svc_rdp -j DNAT --to $ip_cloud_sync_srv

                #--------------
                # zimbra
                #--------------

		comment="WAN mail smtp,smtps,submission,imaps to zimbra"
		pre_add -i $if_wan -d $ip_wan -p tcp -m multiport --dports $svc_smtp,$svc_smtps,$svc_submission,$svc_imaps -j DNAT --to $ip_zimbra_srv

	}

#
#
#
# INPUT
#
#############################################################################
	setup_input_chain()
	#-------------------
	{
		echo Setup INPUT chain

		if [ "$debug_input" == "true" ]; then
			log INPUT-2 "dbg [inp]"
		fi

		comment="established input connections"
		accept_established INPUT-2 -p ALL

		comment="accept loopback interface"
		accept INPUT-2 -i $if_lo

		comment="accept ping"
		accept INPUT-2 -p ICMP --icmp-type 8
		comment="accept ping"
		accept INPUT-2 -p ICMP --icmp-type 11

		comment="accept bcast from lan"
                accept INPUT-2 ! -i $if_wan -d $bcast_my

                comment="accept lan multicast"
                accept INPUT-2 ! -i $if_wan -d $ip_multicast

		#--------------
                # (explicitly droppped)
                #--------------

                comment="drop tftp to srv"
                drop INPUT-2 -i $if_lan -d $ip_my -p udp --dport $svc_tftp

		comment="drop WAN multicast"
		drop INPUT-2 -i $if_wan -d $ip_multicast

		comment="drop WAN multicast ping"
		drop INPUT-2 -i $if_wan -d $ip_multicast_ping

		comment="drop WAN bcast from"
		drop INPUT-2 -i $if_wan -d 192.168.1.255

		#-------------
		# 1688
		#-------------

		comment="accept broadcast 1688"
		accept INPUT-2 -i $if_lan -d 192.168.1.255 -p tcp --dport 1688

		#-------------
		# dhcp
		#-------------

		comment="allow go to dhcp bootps"
		accept INPUT-2 ! -i $if_wan -d $ip_my -p udp --dport $svc_bootps

		comment="allow multicast dhcp"
		accept INPUT-2 ! -i $if_wan -d $ip_multicast -p udp --dport $svc_bootps

		#-----------------------------
		# domain controller
		#-----------------------------

		comment="allow dc docker go to bcast"
		accept INPUT-2 -i $if_dc01 -s $ip_dc01_srv -d $ip_dc01_bcast

		#-------------
		# iperf test
		#-------------

		comment="allow iperf"
                accept INPUT-2 -i $if_lan -d $ip_my -p tcp --dport $svc_iperfs

		#--------------------
		# nas
		#--------------------

		comment="allow ssh to nas"
		accept INPUT-2 -d $ip_my1 -p tcp --dport 40000

                comment="allow samba to nas (udp)"
                accept INPUT-2 -d $ip_my1 -p udp -m multiport --dports $svc_rpcepmap,$svc_netbios_ns,$svc_netbios_dgm

                comment="allow samba to nas (tcp)"
                accept INPUT-2 -d $ip_my1 -p tcp -m multiport --dports $svc_rpcepmap,$svc_netbios_ns,$svc_netbios_ssn,$svc_samba,"$iana_ephemeral_from:$iana_ephemeral_to"

		comment="allow samba bcast (udp)"
		accept INPUT-2 -d $bcast_my -p udp -m multiport --dports $svc_netbios_ns,$svc_netbios_dgm

		#---------------
		# ssh
		#---------------

		comment="accept LAN ssh from"
                accept INPUT-2 -i $if_lan -s $net_lan -d $ip_my -p tcp --dport $svc_ssh

                comment="[TMP] accept WAN from itadmin"
                accept INPUT-2 -i $if_wan -s $ip_sat -d $ip_wan

		#---------------------

#		comment="allow hostmon"
#		accept INPUT-2 -p udp --dport $svc_hostmon

#		comment="[TMP] vnc to srv"
#		accept INPUT-2 -i $if_lan -p tcp --dport 5900

		#---- -- -- --

		if [ "$cert_renew_mode" == "true" ]; then
                        comment="CERT RENEW allow http(s)"
                        accept INPUT-2 -p tcp -m multiport --dports $svc_http,$svc_https
			echo
                fi

		if [[ "$policy_input" == "DROP" && "$log_input" == "true" ]]; then
			#
			# wansilent=true : don't show connection tries from WAN
			# wansilent=false : show connection tries from WAN
			#
			# ( in any case WAN connections defauls to dropped policy )
			#
			wansilent=true

			if $wansilent; then
				# silently drop logging of unwanted wan input traffic
				log INPUT-2 "DROP [inp]" -s $net_privs
			else
				log INPUT-2 "DROP [inp]"
			fi
		fi
	}

#
#
#
# FORWARD
#
#############################################################################
	setup_forward_chain()
	#---------------------
	{
		echo Setup FORWARD chain

		if [ "$debug_forward" == "true" ]; then
			log FORWARD-2 "dbg [fwd]"
		fi

		comment="established forward connections"
		accept_established FORWARD-2 -p ALL

		#--------------
		# (explicitly droppped)
		#--------------


		#------------
                # build
                #------------

                comment="build network output"
                accept FORWARD-2 -i $if_build -s $net_build

                #-----------------
                # ntp
                #-----------------

                comment="allow ntp (udp)"
                accept FORWARD-2 -p udp --dport $svc_ntp

                comment="allow ntp (tcp)"
                accept FORWARD-2 -p tcp --dport $svc_ntp

		#-------------
		# dns
		#-------------

		comment="allow fwd dns (udp)"
		accept FORWARD-2 -p udp --dport $svc_dns

		comment="allow fwd dns (tcp)"
		accept FORWARD-2 -p tcp --dport $svc_dns

		#------------------------
                # domain controller
                #------------------------

		comment="allow dc from net lan,docker (udp)"
                accept FORWARD-2 -o $if_dc01 -s $net_lan_and_dockers -d $ip_dc01_srv -p udp -m multiport --dports \
			$svc_dns,$svc_krb,$svc_netbios_ns,$svc_netbios_dgm,$svc_ldap,$svc_krbpwd

                comment="allow dc from net lan,docker (tcp)"
                accept FORWARD-2 -o $if_dc01 -s $net_lan_and_dockers -d $ip_dc01_srv -p tcp -m multiport --dports \
                        $svc_dns,$svc_krb,$svc_rpcepmap,$svc_netbios_ssn,$svc_ldap,$svc_samba,$svc_krbpwd,$svc_ldaps,$svc_gcat,$svc_gcat_ssl,"$iana_ephemeral_from:$iana_ephemeral_to"

		#---------------
		# nginx
		#----------------

		comment="allow LAN,WAN go to nginx http(s),smtps,submission,imaps"
		accept FORWARD-2 -o $if_nginx -d $ip_nginx_srv -p tcp -m multiport --dports $svc_http,$svc_https,$svc_smtps,$svc_submission,$svc_imaps

		comment="allow LAN,WAN go to nginx 7071 when from lan,itadmin"
		accept FORWARD-2 -o $if_nginx -s $net_lan,$ip_sat -d $ip_nginx_srv -p tcp --dport 7071

		comment="allow nginx go to doc 8080"
                accept FORWARD-2 -i $if_nginx -o $if_doc -s $ip_nginx_srv -d $ip_doc_srv -p tcp --dport 8080

		comment="allow nginx go to cloud"
		accept FORWARD-2 -i $if_nginx -o $if_cloud -s $ip_nginx_srv -d $ip_cloud_srv -p tcp --dport $svc_http

                comment="allow nginx go to zimbra http(s),smtps,submission,imaps,7071"
                accept FORWARD-2 -i $if_nginx -o $if_zimbra -s $ip_nginx_srv -d $ip_zimbra_srv -p tcp -m multiport --dports $svc_http,$svc_https,$svc_smtps,$svc_submission,$svc_imaps,7071

		#--------------------
		# cloud
		#--------------------

		comment="allow cloud go to cloud_psql"
		accept FORWARD-2 -i $if_cloud -o $if_cloud_psql -s $ip_cloud_srv -d $ip_cloud_psql_srv -p tcp --dport $svc_psql

		comment="allow cloud go to http(s)"
		accept FORWARD-2 -i $if_cloud -s $ip_cloud_srv -p tcp -m multiport --dports $svc_http,$svc_https

		comment="allow cloud go to dc01 ldaps"
		accept FORWARD-2 -i $if_cloud -o $if_dc01 -s $ip_cloud_srv -d $ip_dc01_srv -p tcp --dport $svc_ldaps

		#---------------
		# cloud_sync
		#---------------

		comment="allow cloud sync rdp"
		accept FORWARD-2 -o $if_cloud_sync -d $ip_cloud_sync_srv -p tcp --dport $svc_rdp

		comment="allow cloud sync go to http(s)"
		accept FORWARD-2 -i $if_cloud_sync -s $ip_cloud_sync_srv -p tcp -m multiport --dports $svc_http,$svc_https

                #--------------------------------
                # zimbra
                #--------------------------------

                comment="allow zimbra exit to http(s),hkp,smtp"
                accept FORWARD-2 -i $if_zimbra -s $ip_zimbra_srv -p tcp -m multiport --dports $svc_http,$svc_https,$svc_hkp,$svc_smtp

		comment="allow go to zimbra"
		accept FORWARD-2 -o $if_zimbra -d $ip_zimbra_srv -p tcp -m multiport --dports $svc_smtp,$svc_smtps,$svc_submission,$svc_imaps,7071

		#----------------
		# imapsync
		#----------------

		comment="allow imapsync out to imaps"
		accept FORWARD-2 -i $if_imapsync -s $ip_imapsync_srv -p tcp --dport $svc_imaps

		#-----------
                # (gateway)
                #-----------

		comment="drop lan to inet SMTP (prevent SPAM from internal)"
		drop FORWARD-2 -i $if_lan -o $if_wan -s $net_lan -p tcp --dport $svc_smtp

		log FORWARD-2 "GATEWAY---" -i $if_lan -o $if_wan -s $net_lan -d $ip_gw

                comment="forward lan to inet"
		accept FORWARD-2 -i $if_lan -o $if_wan -s $net_lan

		#--------------
		# sec
		#--------------

		comment="http nginx -> sec (80,5000)"
                accept FORWARD-2 -i $if_nginx -o $if_sec -s $ip_nginx_srv -d $ip_sec_srv -p tcp -m multiport --dports $svc_http,5000

		comment="dns from sec0 to dns (udp)"
                accept FORWARD-2 -i $if_sec -o $if_dns -s $ip_sec_srv -d $ip_dns_srv -p udp --dport $svc_dns

		comment="http(s) from sec"
                accept FORWARD-2 -i $if_sec -s $ip_sec_srv -p tcp -m multiport --dports $svc_http,$svc_https

		#--------------
		# [TMP]
		#--------------

		comment="allow rdp from itadmin"
		accept FORWARD-2 -i $if_wan -o $if_lan -s $ip_sat  -p tcp --dport $svc_rdp

		if [[ "$policy_forward" == "DROP" && "$log_forward" == "true" ]]; then
			log FORWARD-2 "DROP [fwd]"
		fi
	}

#
#
#
# OUTPUT
#
#############################################################################
	setup_output_chain()
	#--------------------
	{
		echo Setup OUTPUT chain

		if [ "$debug_output" == "true" ]; then
			log OUTPUT-2 "dbg [out]"
		fi

		comment="established output connections"
		accept_established OUTPUT-2 -p ALL

		comment="allow out to loopback iface"
		accept OUTPUT-2 -o $if_lo

		#---------------
		# dhcp
		#---------------

		comment="allow out to dhcp client"
		accept OUTPUT-2 -o $if_lan -s $ip_my -p udp --dport $svc_bootpc

		#--------------
		# dns
		#--------------

		comment="allow dns (udp)"
		accept OUTPUT-2 -p udp --dport $svc_dns

		comment="allow dns (tcp)"
		accept OUTPUT-2 -p tcp --dport $svc_dns

		#---------------
		# domain controller
		#-------------------

		comment="allow host go to dc (udp)"
                accept OUTPUT-2 -o $if_dc01 -s $ip_dc01_gw -d $ip_dc01_srv -p udp -m multiport --dports \
                       $svc_dns,$svc_krb,$svc_netbios_ns,$svc_netbios_dgm,$svc_ldap,$svc_krbpwd

                comment="allow host go to dc (tcp)"
                accept OUTPUT-2 -o $if_dc01 -s $ip_dc01_gw -d $ip_dc01_srv -p tcp -m multiport --dports \
                        $svc_dns,$svc_krb,$svc_rpcepmap,$svc_netbios_ssn,$svc_ldap,$svc_samba,$svc_krbpwd,$svc_ldaps,$svc_gcat,$svc_gcat_ssl,"$iana_ephemeral_from:$iana_ephemeral_to"

		#-------------------------
		# nas
		#-------------------------

		comment="allow samba netbios_ns,netbios_dgm (udp)"
                accept OUTPUT-2 -o $if_lan -p udp -m multiport --dports $svc_netbios_ns,$svc_netbios_dgm

		#---------------
		# switch
		#---------------

		comment="allow ssh to switch"
		accept OUTPUT-2 -o $if_lan -s $ip_my -d $ip_switch -p tcp --dport $svc_ssh

		comment="allow telnet to switch"
                accept OUTPUT-2 -o $if_lan -s $ip_my -d $ip_switch -p tcp --dport $svc_telnet

		#----------------
		# zimbra
		#----------------

		comment="allow send feedback email"
                accept OUTPUT-2 -o $if_zimbra -s $ip_zimbra_gw -d $ip_zimbra_srv -p tcp --dport $svc_smtps

		#---------------
		# system
		#---------------

		comment="allow ping (icmp 8)"
                accept OUTPUT-2 -p ICMP --icmp-type 8

                comment="allow ping (icmp 11)"
                accept OUTPUT-2 -p ICMP --icmp-type 11

		comment="allow http(s),hkp,git"
                accept OUTPUT-2 -p tcp -m multiport --dports $svc_http,$svc_https,$svc_hkp,$svc_git

		comment="allow ntp (udp)"
                accept OUTPUT-2 -p udp --dport $svc_ntp

                comment="allow ntp (tcp)"
                accept OUTPUT-2 -p tcp --dport $svc_ntp

		comment="allow tdp to lan"
		accept OUTPUT-2 -o $if_lan -p tcp --dport $svc_rdp

		#--------------
		# TEMP
		#--------------

		comment="[TMP] allow ssh to lan"
		accept OUTPUT-2 -o $if_lan -s $ip_my -p tcp --dport $svc_ssh

		if [[ "$policy_output" == "DROP" && "$log_output" == "true" ]]; then
			log OUTPUT-2 "DROP [out]"
		fi
	}

#
#
#
# POSTROUTING
#
#############################################################################
	setup_postrouting()
	#-------------------
	{
		echo Setup POSTROUTING
		# https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/4/html/Security_Guide/s1-firewall-ipt-fwd.html
		# masquerade (less efficient, used for dynamic ip)
                iptables -t nat -A POSTROUTING-2 -o $if_wan -j MASQUERADE

		# https://www.digitalocean.com/community/tutorials/how-to-forward-ports-through-a-linux-gateway-with-iptables
		# snat (more efficient, usable only w/static ip)
		#iptables -t nat -A POSTROUTING-2 -o $if_wan -j SNAT --to-source $ip_wan
	}

#
#
#
# MAIN
#
#############################################################################

	echo Setting firewall

	load_modules

	#setup_network_devices

	reset_iptables

	setup_kernel_level_protection

	#create_ipset_tables pgsql_allowed

	set_iptables_policies

	setup_badpackets

	setup_input_chain

	setup_forward_chain

	setup_output_chain

	setup_prerouting

	setup_postrouting

	enable_ip_forward

	set +x
