# encoding: utf-8

# ------------------------------------------------------------------------------
# Copyright (c) 2006 Novell, Inc. All Rights Reserved.
#
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of version 2 of the GNU General Public License as published by the
# Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, contact Novell, Inc.
#
# To contact Novell about this file by physical or electronic mail, you may find
# current contact information at www.novell.com.
# ------------------------------------------------------------------------------

# File:	include/cluster/helps.ycp
# Package:	Configuration of cluster
# Summary:	Help texts of all the dialogs
# Authors:	Cong Meng <cmeng@novell.com>
#
# $Id: helps.ycp 27914 2006-02-13 14:32:08Z locilka $
module Yast
  module ClusterHelpsInclude
    def initialize_cluster_helps(include_target)
      textdomain "cluster"

      # All helps are here
      @HELPS = {
        "communication" => _(
          "<p><b><big>Transport</big></b><br>This directive controls the transport mechanism used. The default is knet. The transport type can also be set to udpu or udp. <br>Only knet allows crypto or multiple interfaces per node.<br></p>\n" +
          "<p><b><big>IP Version</big></b><br>Specifies version of IP to use for communication. The value can be one of ipv4 (look only for an IPv4 address) , ipv6 (check only IPv6 address) , ipv4-6 (look for all address families and use first IPv4 address found in the list if there is such address, otherwise use first IPv6 address) and ipv6-4 (look for all address families and use first IPv6 address found in the list if there is such address, otherwise use first IPv4 address). <br>Default (if unspecified) is ipv6-4 for knet and udpu transports and ipv4 for udp.<br></p>\n" +
          "<p><b><big>Node List</big></b><br>Specify specific information about nodes in cluster. Every node that should be a member of the membership, and where non-default options are needed. Every node must have at least ring0_addr field filled.<br></p>\n" +
          "<p><b><big>Name</big></b><br>Used mainly with knet transport to identify local node. It's also used by client software (pacemaker). Name is necessary for multiple links/rings configuratioa. Refer to man page(corosync.conf) for detail algorithm of local node name.<br></p>\n" +
          "<p><b><big>Node ID</big></b><br>Node ID is required for each node for Kronosnet mode. It is a 32 bit value specifying the node identifier delivered to the cluster membership service. The node identifier value of zero is reserved and should not be used. If knet is set, this field must be set.<br></p>\n" +
          "<p><b><big>IP X(ringX_addr)</big></b><br>This specifies IP or network hostname address of the particular node. X is a link number. Unicast and Multicast only support 1 link. Kronosnet support up to 8 links.<br></p>\n" +
          "<p><b><big>Interface List</big></b><br>The interface is optional for UDP and knet transports.<br>For knet, multiple interface subsections define parameters for each knet link on the system.<br>For UDPU an interface section is not needed and it is recommended that the nodelist is used to define cluster nodes.<br></p>\n" +
          "<p><b><big>Link Number</big></b><br>The link number for the interface. When using the knet protocol, each interface should specify separate link numbers to uniquely identify to the membership protocol which interface to use for which link. <br>The linknumber must start at 0, the maximum number is 7. <br>For UDP the only supported linknumber is 0.<br></p>\n" +
          "<p><b><big>Knet Transport</big></b><br>The IP transport knet should use, valid values are sctp or udp. <br>Default is udp<br></p>\n" +
          "<p><b><big>Knet Link Priority</big></b><br>This specifies the priority for the link when knet is used in 'passive' mode.<br></p>\n" +
          "<p><b><big>Bind Network Address</big></b><br>UDP only.<br>This  specifies  the  address which the corosync executive should bind.  This address should always end in zero. If the totem traffic should be routed over 192.168.5.92, set bindnetaddr to 192.168.5.0.<br>This may also be an IPV6 address, in which case IPV6 networking will be used. In this case, the full address must be specified and there is no automatic selection of the network interface within a specific subnet as with IPv4. If IPv6 networking is used, the nodeid field must be specified.<br></p>\n" +
          "<p><b><big>Multicast Address</big></b><br>UDP only.<br>This is the multicast address used by corosync executive. The default  should work for most networks, but the network administrator should be queried about a multicast address to use. Avoid 224.x.x.x because this is a \"config\" multicast address.<br>This may also be an IPV6 multicast address, in which case IPV6 networking will be used.  If IPv6 networking is used, the nodeid field must be specified.</p>\n" +
          "<p><b><big>Multicast Port</big></b><br>UDP only.<br>This specifies the UDP port number. It is possible to use the same multicast address on a network with the corosync services configured for different UDP ports.<br></p>\n" +
            "<p><b><big>Link Mode</big></b><br>This specifies the Kronosnet mode, which may be passive, active, or rr (round-robin). passive: the active link with the highest priority (highest number) will be used. If one or more links share the same priority the one with the lowest link ID will be used. active: All active links will be used simultaneously to send traffic. link priority is ignored. rr: Round-Robin policy. Each packet will be sent to the next active link in order.<br>If only one interface directive is specified, passive is automatically chosen.<br>The maximum number of interface directives that is allowed with Kronosnet is 8. For other transports it is 1.<br></p>\n" +
            "<p><b><big>Cluster Name</big></b><br>This specifies the name of cluster and it's used for automatic generating of multicast address. Default is hacluster. For a geo cluster, each cluster must have a unique name.<br></p>\n" +
            "<p><b><big>Auto Generate Node ID</big></b><br>Nodeid is required when using IPv6 or Kronosnet. It will be disabled automatically when Kronosnet or IPv6 address found. Auto node ID enabled will generate nodeid automatically.<br>WARNING: Cluster behavior is undefined if this option is enabled on only a subset of the cluster (for example during a rolling upgrade).<br></p>\n"
        ),
        "corosyncqdevice"      => _(
          "<p><b><big>Model</big></b><br>Specifies the model to be used. This parameter is required.  corosync-qdevice is modular and is able to support multiple different models. The model basically defines what type of arbitrator is used. Currently only 'net' is supported.</p>\n" +
            "<p><b><big>Host</big></b><br>Specifies the IP address or host name of the qnetd server to be used. This parameter is required.</p>\n" +
            "<p><b><big>Port</big></b><br>Specifies TCP port of qnetd server. Default is 5403.</p>\n" +
            "<p><b><big>TLS</big></b><br>Can be one of 'on', 'off' or 'required' and specifies if tls should be used. 'on' means a connection with TLS is attempted first, but if the server doesn't advertise TLS support then non-TLS will be used. 'off' is used then TLS is not required and it's then not even tried. This mode is the only one which doesn't need a properly initialized NSS database. 'required' means TLS is required and if the server doesn't support TLS, qdevice will exit with error message. 'on' need manually change, refer to corosync-qdevice's man page for more details. Default is 'off' in yast.</p>\n" +
            "<p><b><big>Algorithm</big></b><br>Decision algorithm. Can be one of the 'ffsplit' or 'lms'.  (Actually there are also 'test' and '2nodelms', both of which are mainly for developers and shouldn't be used for production clusters, so yast will convert to 'ffsplit' automatically). For a description of what each algorithm means and how the algorithms differ see their individual sections.  Default value is ffsplit.</p>\n" +
            "<p><b><big>Tie breaker</big></b><br>Can be one of 'lowest', 'highest' or 'valid_node_id' (number) values. It's used as a fallback if qdevice has to decide between two or more equal partitions. 'lowest' means the partition with the lowest node id is chosen. 'highest' means the partition with highest node id is chosen. And 'valid_node_id' means that the partition containing the node with the given node id is chosen. Default is 'lowest'.</p>\n" +
            "<p><b><big>Qdevice Heuristics</big></b><br>Subsection of Qdevice. " \
            "Heuristics are set of commands executed locally on startup, cluster membership change, " \
            "successful connect to corosync-qnetd and optionally also at regular times. Commands are executed in parallel. " \
            "When *all* commands finish successfully (their return error code is zero) on time, heuristics have passed, " \
            "otherwise they have failed. The heuristics result is sent to corosync-qnetd and there it's used in calculations " \
            "to determine which partition should be quorate.</p>\n" +
            "<p><b><big>Heuristics Mode</big></b><br>Can be one of on, sync or off and specifies mode of operation of heuristics. " \
            "Default is off, which  means  heuristics are disabled. When sync is set, heuristics are executed only during startup, " \
            "membership change and when connection to corosync-qnetd is established. " \
            "When heuristics should be running also on regular basis, this option should be set to on value.</p>\n" +
            "<p><b><big>Heuristics Timeout</big></b><br>Specifies maximum time in milliseconds. " \
            "How long corosync-qdevice waits till the heuristics commands finish. " \
            "If some command doesn't finish before the timeout, it's killed and heuristics fail. " \
            "This timeout is used for heuristics executed at regular times. " \
            "Default value is half of the quorum.device.timeout, so 5000.</p>\n" +
            "<p><b><big>Heuristics Sync_timeout</big></b><br>Similar to quorum.device.heuristics.timeout but used during membership changes. " \
            "Default value is half of the quorum.device.sync_timeout, so 15000.</p>\n" +
            "<p><b><big>Heuristics Interval</big></b><br>Specifies interval between two regular heuristics execution. " \
            "Default value is 3 * quorum.device.timeout, so 30000.</p>\n" +
            "<p><b><big>Heuristics exec_NAME</big></b><br>Defines executables. " \
            "*NAME* can be arbitrary valid cmap key name string and it has no special meaning. " \
            "The value of this variable must contain a command to execute. " \
            "The value is parsed (split) into arguments similarly as Bourne shell would do. " \
            "Quoting is possible by using backslash and double quotes. " \
            "<br>For example, Name(exec_check_master), Value(/etc/corosync/qdevice/check_master.sh)</p>\n"
        ),
        "security"      => _(
          "\n" +
            "<p><b><big>Enable Security Auth</big></b><br>This specifies that HMAC/SHA1 authentication should be used to authenticate all messages. It further specifies that all data should be encrypted with the sober128 encryption algorithm to protect data from eavesdropping. Enabling this option adds a 36 byte header to every message sent by totem which reduces total throughput. Encryption and authentication consume 75% of CPU cycles in aisexec as measured with gprof when enabled. For 100Mbit networks with 1500 MTU frame transmissions: A throughput of 9Mb/s is possible with 100% cpu utilization when this option is enabled on 3GHz cpus. A throughput of 10Mb/s is possible wth 20% cpu utilization when this option is  disabled on 3GHz cpus. For gig-e networks with large frame transmissions: A throughput of 20Mb/s is possible when this  option  is  enabled  on  3GHz cpus. A throughput of 60Mb/s is possible when this option is disabled on 3GHz cpus.  The default is off. <br></p>\n" +
            "<p><b><big>Crypto Model</big></b><br>This specifies which cryptographic library should be used by knet. Options are nss and openssl.<br>The default is nss.<br></p>\n" +
            "<p><b><big>Crypto Hash</big></b><br>This specifies which HMAC authentication should be used to authenticate all messages. Valid values are none (no authentication), md5, sha1, sha256, sha384 and sha512. Encrypted transmission is only supported for the knet transport.<br>The default is none.<br></p>\n" +
            "<p><b><big>Crypto Cipher</big></b><br>This specifies which cipher should be used to encrypt all messages. Valid values are none (no encryption), aes256, aes192 and aes128. Enabling crypto_cipher, requires also enabling of crypto_hash. Encrypted transmission is only supported for the knet transport.<br>The default is none.<br></p>\n"
        ),
        "service"       => _(
          "\n" +
            "\t\t\t<p><b><big>Cluster start at booting time enable/disable</big></b><br>Start or not start the whole cluster at booting time. Service include: pacemaker, corosync, corosync-qdevice(If enabled corosyncqdevice).</p>\n" +
            "\t\t\t<p><b><big>Cluster start/stop now</big></b><br>Start or stop the whole cluster right now. Service include: pacemaker, corosync, corosync-qdevice(If enabled corosyncqdevice).</p>\n" +
            "\t\t\t<p><b><big>Firewall Settings</big></b><br>Enable the port when Firewall is enabled</p>\n" +
            "\t\t\t"
        ),
        "csync2"        => _(
          "\n" +
            "\t\t<p><b><big>Sync Host</big></b><br>The hostnames used here must be the local hostnames of the cluster nodes. That means you must use exactly the same string as printed out by the hostname command.</p>\n" +
            "\t\t<p><b><big>Sync File</big></b><br>The full absolute filename to be synced.</p>\n" +
            "\t\t<p><b><big>Pre-Shared-Keys</big></b><br>Authentication is performed using the IP addresses and pre-shared-keys in Csync2. The key file is generated with csync2 -k /etc/csync2/key_hagroup. The file key_hagroup should be copied to all members of the cluster manually after it's created.</p>\n" +
            "\t"
        ),
        "conntrack"     => _(
          "\n" +
            "\t\t<p><b><big>Dedicated Interface</big></b><br>A dedicated network interface for syncing. The interface must support multicast, and is UP for using. You may have to have it pre-configured. </p>\n" +
            "\t\t<p><b><big>IP</big></b><br>The IPv4 address assigned to the dedicated network interface. This is detected automatically.</p>\n" +
            "\t\t<p><b><big>Multicast Address</big></b><br>The multicast address to be used for syncing.</p>\n" +
            "\t\t<p><b><big>Group Number</big></b><br>A numeric ID indicate the group for syncing.</p>\n" +
            "\t"
        ),
        # Read dialog help 1/2
        "read"          => _(
          "<p><b><big>Initializing cluster Configuration</big></b><br>\nPlease wait...<br></p>\n"
        ) +
          # Read dialog help 2/2
          _(
            "<p><b><big>Aborting Initialization:</big></b><br>\nSafely abort the configuration utility by pressing <b>Abort</b> now.</p>\n"
          ),
        # Write dialog help 1/2
        "write"         => _(
          "<p><b><big>Saving cluster Configuration</big></b><br>\nPlease wait...<br></p>\n"
        ) +
          # Write dialog help 2/2
          _(
            "<p><b><big>Aborting Saving:</big></b><br>\n" +
              "Abort the save procedure by pressing <b>Abort</b>.\n" +
              "An additional dialog informs whether it is safe to do so.\n" +
              "</p>\n"
          )
      } 

      # EOF
    end
  end
end
