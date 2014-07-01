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
          "<p><b><big>Bind Network Address</big></b><br>This  specifies  the  address which the openais executive should bind.  This address should always end in  zero.   If  the  totem traffic  should  be routed over 192.168.5.92, set bindnetaddr to 192.168.5.0.<br>This may also be an IPV6 address, in which case IPV6  networking will  be used.  In this case, the full address must be specified and there is no automatic selection  of  the  network  interface within a specific subnet as with IPv4. If IPv6 networking is used, the nodeid field must be specified.<br></p>\n" +
            "<p><b><big>Multicast Address</big></b><br>This is the multicast address used by  openais  executive.   The default  should work for most networks, but the network administrator should be queried  about  a  multicast  address  to  use.  Avoid 224.x.x.x because this is a \"config\" multicast address.<br>This  may  also be an IPV6 multicast address, in which case IPV6 networking will be used.  If IPv6 networking is used, the nodeid field must be specified.</p>\n" +
            "<p><b><big>Port</big></b><br>This  specifies  the UDP port number.  It is possible to use the same multicast address on a network with  the  openais  services configured for different UDP ports.<br></p>\n" +
            "<p><b><big>Member Address</big></b><br>This list specifies all the nodes in the cluster by IP address. This could be configurable when using udpu <br></p>\n" +
            "<p><b><big>Node ID</big></b><br>This  configuration  option  is  optional  when  using  IPv4 and required when using IPv6.  This is a 32 bit value specifying the node identifier delivered to the cluster membership service.  If this is not specified with IPv4, the node id will be  determined from  the  32  bit  IP address the system to which the system is bound with ring identifier of 0.  The node identifier  value  of zero is reserved and should not be used.<br></p>\n" +
            "<p><b><big>rrp_mode</big></b><br>This specifies the mode of redundant ring, which  may  be  none, active,  or  passive.   Active replication offers slightly lower latency from transmit to delivery in faulty network environments but  with less performance.  Passive replication may nearly double the speed of the totem  protocol  if  the  protocol  doesn't become  cpu bound.  The final option is none, in which case only one network interface will be used to operate the  totem  protocol.  If  only one interface directive is specified, none is automatically chosen.  If multiple interface directives  are  specified, only active or passive may be chosen.<br></p>\n" +
            "<p><b><big>Expected votes</big></b><br>Expect vote number for voting quorum.  Will be automatically calculated when the nodelist {} section is present in corosync.conf or can be specified in the quorum {} section.<br></p>\n" +
            "<p><b><big>Auto Generate Node ID</big></b><br>Nodeid is required when using IPv6. Auto node ID enabled will generate nodeid automatically.<br></p>\n"
        ),
        "security"      => _(
          "\n" +
            "<p><b><big>Threads</big></b><br>This directive controls how many threads are used to encrypt and send multicast messages.  If secauth is off, the  protocol  will never  use  threaded  sending.  If secauth is on, this directive allows systems to be  configured  to  use  multiple  threads  to encrypt and send multicast messages.  A  thread  directive of 0 indicates that no threaded send should be used.  This mode offers best performance for non-SMP systems.  The default is 0. <br></p>\n" +
            "<p><b><big>Enable Security Auth</big></b><br>This  specifies  that HMAC/SHA1 authentication should be used to authenticate all messages.  It further specifies that  all  data should  be  encrypted  with the sober128 encryption algorithm to protect data from eavesdropping.  Enabling this option adds a 36 byte header to every message sent by totem which reduces total throughput.  Encryption and authentication consume 75% of CPU cycles in aisexec as  measured  with gprof when enabled.  For  100mbit  networks  with  1500  MTU  frame  transmissions: A throughput of 9mb/sec is possible with 100% cpu utilization when this  option  is enabled on 3ghz cpus.  A throughput of 10mb/sec is possible wth 20% cpu utilization when this option is  disabled on 3ghz cpus.  For  gig-e networks with large frame transmissions: A throughput of 20mb/sec is possible when this  option  is  enabled  on  3ghz cpus.   A throughput of 60mb/sec is possible when this option is disabled on 3ghz cpus.  The default is on. <br></p>\n"
        ),
        "service"       => _(
          "\n" +
            "\t\t\t<p><b><big>Booting</big></b><br>Starting corosync service during boot or not</p>\n" +
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
