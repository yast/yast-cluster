#encoding: utf-8

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

# File:	include/cluster/wizards.ycp
# Package:	Configuration of cluster
# Summary:	Wizards definitions
# Authors:	Cong Meng <cmeng@novell.com>
#
# $Id: wizards.ycp 27914 2006-02-13 14:32:08Z locilka $
require 'set'
require "y2firewall/firewalld"
require "yast2/systemd/socket"

module Yast
  module ClusterDialogsInclude
    def initialize_cluster_dialogs(include_target)
      textdomain "cluster"

      Yast.import "Label"
      Yast.import "Wizard"
      Yast.import "Cluster"
      Yast.import "IP"
      Yast.import "Popup"
      Yast.import "Service"
      Yast.import "Report"
      Yast.import "CWMFirewallInterfaces"

      Yast.include include_target, "cluster/helps.rb"
      Yast.include include_target, "cluster/common.rb"

      @csync2_suggest_files = [
        "/etc/corosync/corosync.conf",
        "/etc/corosync/authkey",
        "/etc/sysconfig/pacemaker",
        "/etc/drbd.d",
        "/etc/drbd.conf",
        "/etc/lvm/lvm.conf",
        "/etc/multipath.conf",
        "/etc/ha.d/ldirectord.cf",
        "/etc/ctdb/nodes",
        "/etc/samba/smb.conf",
        "/etc/booth",
        "/etc/sysconfig/sbd",
        "/etc/sysconfig/nfs",
        "/etc/csync2/csync2.cfg",
        "/etc/csync2/key_hagroup",
        "/etc/modules-load.d/watchdog.conf"
      ]

      @csync2_port = "30865"
      @csync2_package = "csync2"

      # This is the list of usable interface for conntrackd
      @usable_interface = []
    end

    # IP check between address and IP Version
    def ip_matching_check(ip_address, ip_version)
      if ip_version.to_s == "ipv6-4" || ip_version.to_s == "ipv4-6"
        return IP.Check4(ip_address.to_s) || IP.Check6(ip_address.to_s)
      elsif ip_version.to_s == "ipv4"
        return IP.Check4(ip_address.to_s)
      elsif ip_version.to_s == "ipv6"
        return IP.Check6(ip_address.to_s)
      else
        return false
      end

    end

    def _has_ipv6_addr()
      has_ipv6 = false

      if not Cluster.node_list.empty?
        Cluster.node_list.each do |node|
          node.default = []
          iplist = node["IPs"]

          iplist.each do |ip|
            if IP.Check6(ip)
              has_ipv6 = true
              break
            end
          end # end iplist loop
        end # end node loop
      end # end node_list check

      if not Cluster.interface_list.empty?
        Cluster.interface_list.each do |iface|
          ["bindnetaddr", "mcastaddr"].each do |ele|
            if iface.has_key?(ele)
              if IP.Check6(iface[ele])
                has_ipv6 = true
                break
              end
            end
          end
        end # end interface loop
      end # end interface_list check

      has_ipv6
    end

    # return `cancel or a string
    def text_input_dialog(title, value)
      ret = nil

      UI.OpenDialog(
        MarginBox(
          1,
          1,
          VBox(
            MinWidth(100, InputField(Id(:text), title, value)),
            VSpacing(1),
            Right(
              HBox(
                PushButton(Id(:ok), _("OK")),
                PushButton(Id(:cancel), _("Cancel"))
              )
            )
          )
        )
      )

      ret = UI.UserInput
      ret = UI.QueryWidget(:text, :Value) if ret == :ok
      UI.CloseDialog
      deep_copy(ret)
    end

    def _get_ip_table_items(iplist=[])
      index = 0
      table_items = []

      iplist.each do |ip|
        items = Item(Id(index))
        items = Builtins.add(items, index)
        items = Builtins.add(items, ip)
        index += 1

        table_items.push(items)
      end

      deep_copy(table_items)
    end

    def fill_node_ips(iplist=[])
      current = 0

      table_items = _get_ip_table_items(iplist)

      current = UI.QueryWidget(:iplist_table, :CurrentItem).to_i
      current = 0 if current == nil
      current = table_items.size - 1 if current >= table_items.size

      UI.ChangeWidget(:iplist_table, :Items, table_items)
      UI.ChangeWidget(:iplist_table, :CurrentItem, current)

      nil
    end

    def _valid_iplist(iplist=[], ip_version="ipv6-4")
      if iplist.empty?
        Popup.Message(_("At least one ring/IP has to be fulfilled"))
        return false
      end

      if iplist.size > 8
        Popup.Message(_("Support at most 8 rings"))
        return false
      end

      iplist.each do |ip|
        if !ip_matching_check(ip, ip_version)
          Popup.Message(_("Invalid IP address found: ") + ip)
          return false
        end
      end

      true
    end

    def switch_iplist_button(iplist=[])
      haveip = true

      if iplist.empty?
        haveip = false
      end

      UI.ChangeWidget(Id(:ip_add), :Enabled, true)
      UI.ChangeWidget(Id(:ip_edit), :Enabled, haveip)
      UI.ChangeWidget(Id(:ip_del), :Enabled, haveip)

      nil
    end

    def nodelist_input_dialog(value={}, ip_version="ipv6-4")
      value.default = ""

      UI.OpenDialog(
        MarginBox(
          1,
          1,
          VBox(
            HBox(
            MinWidth(40, InputField(Id(:mynodename), Opt(:hstretch), _("Node Name:"), value["name"])),
            HSpacing(1),
            MinWidth(20, InputField(Id(:mynodeid), Opt(:hstretch), _("Node ID:"), value["nodeid"])),
            ),
            VSpacing(1),
            VBox(
              Opt(:hvstretch),
              MinSize(20, 10,
                Table(
                  Id(:iplist_table),
                  Opt(:hstretch, :vstretch),
                  Header(_("Link number"), _("IP addresses")),
                  []
                ),
              ),
              VSpacing(1),
              HBox(
                PushButton(Id(:ip_add), _("Add")),
                PushButton(Id(:ip_edit), _("Edit")),
                PushButton(Id(:ip_del), _("Del")),
              )
            ),
            VSpacing(1),
            Right(
              HBox(
                PushButton(Id(:ok), _("OK")),
                PushButton(Id(:cancel), _("Cancel"))
              )
            )
          )
        )
      )

      value.default = []
      iplist = deep_copy(value["IPs"])

      while true
        switch_iplist_button(iplist)
        fill_node_ips(iplist)

        ret = UI.UserInput

        if ret == :ip_add
          ret = text_input_dialog(_("Add a IP address"), "")
          next if ret == :cancel
          iplist.push(ret)
        end

        if ret == :ip_edit
          current = 0

          current = UI.QueryWidget(:iplist_table, :CurrentItem).to_i
          ret = text_input_dialog(
            _("Edit the IP address"),
            iplist[current]
          )
          next if ret == :cancel
          iplist[current] = ret.to_s
        end

        if ret == :ip_del
          current = 0
          current = UI.QueryWidget(:iplist_table, :CurrentItem).to_i
          iplist.delete_at(current)
        end

        if ret == :ok
          if !_valid_iplist(iplist, ip_version)
            UI.SetFocus(:iplist_table)
            next
          end

          ret = {}

          if UI.QueryWidget(:mynodename, :Value) != ""
            ret["name"] = UI.QueryWidget(:mynodename, :Value)
          end

          if UI.QueryWidget(:mynodeid, :Value) != ""
            ret["nodeid"] = UI.QueryWidget(:mynodeid, :Value)
          end

          ret["IPs"] = iplist
          break

        elsif ret == :cancel
          break
        end

      end

      UI.CloseDialog
      deep_copy(ret)
    end

    def switch_interface_button(transport)
      # transport "udpu" should not reach here
      knet = true
      if transport != "knet"
        knet = false
      end

      UI.ChangeWidget(Id(:knet_link_priority), :Enabled, knet)
      UI.ChangeWidget(Id(:knet_transport), :Enabled, knet)

      UI.ChangeWidget(Id(:bindnetaddr), :Enabled, !knet)
      UI.ChangeWidget(Id(:mcastaddr), :Enabled, !knet)
      UI.ChangeWidget(Id(:mcastport), :Enabled, !knet)

      nil
    end

    def interface_input_dialog(value, transport="knet")
      existing_ips = _get_bind_address()
      if value.has_key?("bindnetaddr")
        tmp = [value["bindnetaddr"], ""]

        if existing_ips.include?(value["bindnetaddr"])
          existing_ips.delete(value["bindnetaddr"])
        end
      else
        tmp = [""]
      end
      bindaddr = tmp + existing_ips

      if value.has_key?("linknumber")
        links = [value["linknumber"], ""]
      else
        links = [""]
      end
      if !Cluster.node_list.empty?
        tmp = Cluster.node_list[0]["IPs"].size
        tmp.times do |index|
          if !links.include?(index)
            links.push(index.to_s)
          end
        end
      end

      value.default=""

      UI.OpenDialog(
        MarginBox(
          1,
          1,
          VBox(
            HBox(
              ComboBox(
                Id(:linknumber),
                Opt(:editable, :hstretch),
                _("Link Number"),
                links
              ),
              HSpacing(1),
              ComboBox(
                Id(:knet_transport), Opt(:hstretch), _("Knet Transport"),
                [
                Item(Id(""), ""),
                Item(Id("udp"), "udp"),
                Item(Id("sctp"), "sctp"),
                ]
              ),
              HSpacing(1),
              MinWidth(40, InputField(Id(:knet_link_priority), _("Knet Link Priority"),
                                      value["knet_link_priority"])),
            ),
            VSpacing(1),
            HBox(
              ComboBox(
                Id(:bindnetaddr),
                Opt(:editable, :hstretch),
                _("Bind Network Address:"),
                bindaddr
              ),
              HSpacing(1),
              MinWidth(40, InputField(Id(:mcastaddr), _("Mcast Address"), value["mcastaddr"])),
              HSpacing(1),
              MinWidth(20, InputField(Id(:mcastport), _("Mcast Port") , value["mcastport"])),
            ),
            VSpacing(1),
            Right(
              HBox(
                PushButton(Id(:ok), _("OK")),
                PushButton(Id(:cancel), _("Cancel"))
              )
            )
          )
        )
      )

      UI.ChangeWidget(:linknumber, :ValidChars, "0123456789")
      UI.ChangeWidget(:mcastport, :ValidChars, "0123456789")
      UI.ChangeWidget(:knet_link_priority, :ValidChars, "0123456789")
      UI.ChangeWidget(Id(:knet_transport), :Value, value["knet_transport"])

      switch_interface_button(transport)

      ret = UI.UserInput
      if ret == :ok
        ret = {}

        ret["linknumber"] = UI.QueryWidget(:linknumber, :Value)
        if transport == "knet"
          ret["knet_transport"] = UI.QueryWidget(:knet_transport, :Value)
          ret["knet_link_priority"] = UI.QueryWidget(:knet_link_priority, :Value)
        elsif transport == "udp"
          ret["bindnetaddr"] = UI.QueryWidget(:bindnetaddr, :Value)
          ret["mcastaddr"] = UI.QueryWidget(:mcastaddr, :Value)
          ret["mcastport"] = UI.QueryWidget(:mcastport, :Value)
        end

        ret.each_key do |key|
          if ret[key] == ""
            ret.delete(key)
          end
        end

      end

      UI.CloseDialog
      deep_copy(ret)
    end

    def ValidIPFamily
      if _has_ipv6_addr()
        if UI.QueryWidget(Id(:ip_version), :Value) == "ipv4"
          Popup.Message(_("Found IPv6 address configured with IP version ipv4"))
          UI.SetFocus(:ip_version)
          return false
        end

        # IPv6 should add node ID manually
        if UI.QueryWidget(Id(:autoid), :Value)
          Popup.Message(_("Auto generate Node ID must be disabled when IPv6 address assigned"))
          UI.SetFocus(:autoid)
          return false
        end

        # All nodes on the same link have the same IP family
        ipverlist = []
        Cluster.node_list[0]["IPs"].each do |ip|
          ipverlist.push(IP.Check4(ip))
        end
        ringnum = ipverlist.size

        # Ring number is identical between nodes
        Cluster.node_list.each do |node|
          ret = true

          ringnum.times do |index|
            if ipverlist[index]
              if IP.Check6(node["IPs"][index])
                ret = false
              end
            else
              if IP.Check4(node["IPs"][index])
                ret = false
              end
            end
          end

          if !ret
            Popup.Message(_("All nodes on the same link should have the same IP family"))
            UI.SetFocus(:nodelist)
            return false
          end
        end
      end # end _has_ipv6_addr()

      true
    end

    def ValidNodeID
      i = 0
      # Set need to require 'set'
      idset = Set[]

      Cluster.node_list.each do |node|
        if !node.has_key?("nodeid")
          Popup.Message(_("Node ID has to be fulfilled or select Auto Generate Node ID when allowed"))
          UI.ChangeWidget(:nodelist, :CurrentItem, i)
          i = 0
          break
        end

        if node["nodeid"].to_i <= 0
          Popup.Message(_("Node ID has to be fulfilled with a positive integer or select Auto Generate Node ID when allowed"))
          UI.ChangeWidget(:nodelist, :CurrentItem, i)
          i = 0
          break
        end

        if idset.include?(node["nodeid"].to_i)
          Popup.Message(_("Node ID must be unique"))
          UI.ChangeWidget(:nodelist, :CurrentItem, i)
          i = 0
          break
        end

        idset << node["nodeid"].to_i
        i += 1
      end

      if i == 0
        return false
      end

      true
    end

    # BNC#871970, change member address struct
    def ValidateCommunication
      i = 0

      # Must have cluster name
      if UI.QueryWidget(Id(:cluster_name), :Value) == ""
        Popup.Message(_("The cluster name has to be fulfilled"))
        UI.SetFocus(:cluster_name)
        return false
      end

      # Only one ring supported for Unicast or Multicast
      if (UI.QueryWidget(Id(:transport), :Value) == "udp" ||
          UI.QueryWidget(Id(:transport), :Value) == "udpu") && Cluster.interface_list.size > 1
        Popup.Message(_("Limited to one ring when Unicast or Multicast.\nPlease use Kronosnet"))
        UI.SetFocus(:ifacelist)
        return false
      end

      # FIXME: if multicast still support not configure node list?
      if Cluster.node_list.size <= 0
        Popup.Message(_("The node list has to be fulfilled"))
        UI.SetFocus(:nodelist)
        return false
      end

      # Interface number must be either 0 or match ring number
      ringnum = Cluster.node_list[0]["IPs"].size
      if ringnum == 0
        Popup.Message(_("Every node must have at least one ring address filled"))
        UI.SetFocus(:nodelist)
        return false
      elsif ringnum > 8
        Popup.Message(_("Support at most 8 rings"))
        UI.SetFocus(:nodelist)
        return false
      elsif ringnum > 1 && UI.QueryWidget(Id(:transport), :Value) != "knet"
        Popup.Message(_("Muiticast and Unicast no longer support multiple rings.\nPlease use Kronosnet"))
        UI.SetFocus(:transport)
        return false
      elsif ringnum == 1 && UI.QueryWidget(Id(:linkmode), :Value) != "passive"
        Popup.Message(_("Only one interface is specified, passive linkmode is automatically be chosen"))
        UI.ChangeWidget(Id(:linkmode), :Value, "passive")
        UI.SetFocus(:linkmode)
      end

      # node name must be unique if assigned
      nameset = Set[]
      Cluster.node_list.each do |node|
        if node.has_key?("name") && nameset.include?(node["name"])
          Popup.Message(_("Node name must be unique"))
          UI.SetFocus(:nodelist)
          return false
        end
        nameset << node["name"]
      end

      if UI.QueryWidget(Id(:transport), :Value) == "knet"
        # Kronosnet must assign node ID
        if UI.QueryWidget(Id(:autoid), :Value)
          Popup.Message(_("Should not use auto generate Node ID when Kronosnet"))
          UI.SetFocus(:autoid)
          return false
        end

        # Multiple links/rings must assign node name
        Cluster.node_list.each do |node|
          if !node.has_key?("name") && ringnum > 1
            Popup.Message(_("Need to assign each node a name when multiple rings/links"))
            UI.SetFocus(:nodelist)
            return false
          end
        end

        # Kronosnet transport should be udp/sctp
        if not Cluster.interface_list.empty?
          Cluster.interface_list.each do |iface|
            if iface.has_key?("knet_transport")
              if !["udp", "sctp"].include?(iface["knet_transport"])
                Popup.Message(_("Kronosnet transport should either udp or sctp"))
                UI.SetFocus(:ifacelist)
                return false
              end
            end
          end # end iface loop
        end

      elsif UI.QueryWidget(Id(:transport), :Value) == "udp"
        # Should not have knet parameters in Multicast
        # Won't save interface list in Unicast anyway
        if not Cluster.interface_list.empty?
          Cluster.interface_list.each do |iface|
            if iface.has_key?("knet_transport") || iface.has_key?("knet_link_priority")
              Popup.Message(_("Should not config ket link priority/transport when using Unicast or Multicast"))
              UI.SetFocus(:ifacelist)
              return false
            end
          end
        end
      end # end :transport check

      # No duplicate ring number
      Cluster.node_list.each do |node|
        if node["IPs"].size != ringnum
          Popup.Message(_("Ring number must identical between nodes"))
          UI.SetFocus(:nodelist)
          return false
        end
      end

      # Interface number should match ring number
      if not Cluster.interface_list.empty?
        if Cluster.interface_list.size > ringnum
          Popup.Message(_("Number of interfaces should match or smaller than number of rings"))
          UI.SetFocus(:ifacelist)
          return false
        end

        if UI.QueryWidget(Id(:transport), :Value) == "udp"
          Cluster.interface_list.each do |iface|
            if iface["linknumber"].to_i != 0
              Popup.Message(_("Multicast the only supported linknumber is 0"))
              UI.SetFocus(:ifacelist)
              return false
            end
          end

        else
          linkset = Set[]
          Cluster.interface_list.each do |iface|
            if iface["linknumber"].to_i > ringnum - 1
              Popup.Message(_("Interface link number should smaller than rings number: ") +
                            (ringnum - 1).to_s)
              UI.SetFocus(:ifacelist)
              return false
            elsif iface["linknumber"].to_i > 7
              Popup.Message(_("Maximum allowed interface ring number is 7"))
              UI.SetFocus(:ifacelist)
              return false
            end

            # Link number must be unique
            if linkset.include?(iface["linknumber"].to_i)
              Popup.Message(_("Interface Link number must be unique"))
              UI.SetFocus(:ifacelist)
              return false
            end

            linkset << iface["linknumber"].to_i

            if UI.QueryWidget(Id(:transport), :Value) == "knet"
              # Should not have ["bindnetaddr", "mcastaddr", "mcastport"] configured
              iface.each_key do |key|
                if ["bindnetaddr", "mcastaddr", "mcastport"].include?(key)
                  Popup.Message(_("Should not configure bind address/multicast address/multicast port in Kronosnet"))
                  UI.SetFocus(:ifacelist)
                  return false
                end
              end
            end

          end # end interface_list loop
        end # end :transport
      end # end interface_list not empty

      ret = ValidIPFamily()
      if !ret
         return false
      end

      if !UI.QueryWidget(Id(:autoid), :Value)
        ret = ValidNodeID()
        if !ret
           UI.SetFocus(Id(:nodelist))
           return false
        end
      end

      true
    end

    def SaveCommunication
      # FIXME: if need to notify user will disable secauth automatically when udp/udpu
      ringnum = Cluster.node_list[0]["IPs"].size
      if ringnum == 1
        Cluster.link_mode = "passive"
      else
        Cluster.link_mode = UI.QueryWidget(Id(:linkmode), :Value).to_s
      end

      Cluster.autoid = Convert.to_boolean(UI.QueryWidget(Id(:autoid), :Value))
      Cluster.cluster_name = UI.QueryWidget(Id(:cluster_name), :Value)
      Cluster.transport = Convert.to_string(
        UI.QueryWidget(Id(:transport), :Value)
      )
      Cluster.ip_version = UI.QueryWidget(Id(:ip_version), :Value).to_s

      # For UDPU an interface section is not needed
      if UI.QueryWidget(Id(:transport), :Value) == "udpu"
        Cluster.interface_list = []
      end

      nil
    end

    #only work when IPv4
    def calc_network_addr(ip, mask)
      IP.ToString(
        Ops.bitwise_and(
          IP.ToInteger(ip),
          Ops.shift_left(4294967295, Ops.subtract(32, mask.to_i))
        )
      )
    end

    def _get_bind_address
      result = {}

      result = Convert.to_map(
        SCR.Execute(
          path(".target.bash_output"),
          "/sbin/ip addr show scope global | grep inet | awk '{print $2}' | awk -F'/' '{print $1, $2}'"
        )
      )

      ips = []
      if Builtins.size(Ops.get_string(result, "stdout", "")) != 0
        ip_masks = Builtins.splitstring(
          Ops.get_string(result, "stdout", ""),
          "\n"
        )
        Builtins.foreach(ip_masks) do |s|
          ip_mask_list = Builtins.splitstring(s, " ")
          ip = Ops.get(ip_mask_list, 0, "")
          mask = Ops.get(ip_mask_list, 1, "")
          ip4 = false
          ip4 = IP.Check4(ip)
          if ip4
            ips = Builtins.add(
              ips,
              calc_network_addr(ip, mask)
            )
          end
        end
      end

      deep_copy(ips)
    end

    def _get_nodelist_table_items()
      table_items = []
      index = 0

      Cluster.node_list.each do |node|
        iplist = Ops.get(node, "IPs")

        items = Item(Id(index))

        node.default = ""
        items = Builtins.add(items, node["name"])
        items = Builtins.add(items, node["nodeid"])

        ip_number = 0
        iplist.each do |ip|
          ip_number += 1
          if ip_number > 3
            items = Builtins.add(items, "...")
            break
          end
          items = Builtins.add(items, ip)
        end

        index += 1
        table_items.push(items)
      end

      deep_copy(table_items)
    end

    def _get_interface_table_items
      table_items = []
      num = 0

      Cluster.interface_list.each do |iface|
        items = Item(Id(num))

        iface.default = ""
        items = Builtins.add(items, iface["linknumber"])
        items = Builtins.add(items, iface["knet_transport"])
        items = Builtins.add(items, iface["knet_link_priority"])
        items = Builtins.add(items, iface["bindnetaddr"])
        items = Builtins.add(items, iface["mcastaddr"])
        items = Builtins.add(items, iface["mcastport"])

        table_items.push(items)
        num += 1
      end

      deep_copy(table_items)
    end

    # BNC#871970, change member address struct to memberaddr
    def CommunicationLayout
      hid = VBox(
        HBox(
          ComboBox(
            Id(:transport),
            Opt(:hstretch, :notify),
            _("Transport:"),
            [
            Item(Id("knet"), "Kronosnet"),
            Item(Id("udp"), "Multicast"),
            Item(Id("udpu"), "Unicast")
            ]
          ),
          ComboBox(
            Id(:ip_version),
            Opt(:hstretch, :notify),
            _("IP Version:"),
            [
              Item(Id("ipv6-4"), "ipv6-4"),
              Item(Id("ipv4-6"), "ipv4-6"),
              Item(Id("ipv4"), "ipv4"),
              Item(Id("ipv6"), "ipv6")
            ]
          )
        )
      )

      # Initialize node list
      table_items = _get_nodelist_table_items()

      nodelist_table = VBox(
        Left(Label(_("Node List:"))),
        Table(Id(:nodelist), Opt(:hstretch),
              Header(_("Name"), _("Node ID"), _("IP1"), _("IP2"),
                     _("IP3"), _("More IPs...")), table_items),
        Right(HBox(
          PushButton(Id(:nodelist_add), "Add"),
          PushButton(Id(:nodelist_edit), "Edit"),
          PushButton(Id(:nodelist_del), "Del"),
        )),
      )

      # Initialize interface list
      table_items = _get_interface_table_items()

      iface_table = VBox(
        Left(Label(_("Interface List: (Optional)"))),
        Table(Id(:ifacelist), Opt(:hstretch),
              Header(_("Link Number"), _("Knet Transport"), _("Knet Link Priority"),
                     _("Bind Address"), _("Mcast Addr"), _("Mcast port")), table_items),
        Right(HBox(
          PushButton(Id(:ifacelist_add), "Add"),
          PushButton(Id(:ifacelist_edit), "Edit"),
          PushButton(Id(:ifacelist_del), "De&l"),
        )),
      )

      nid = VBox(
        HBox(
          Left(InputField(Id(:cluster_name),Opt(:hstretch), _("Cluster Name:"),"hacluster")),
          ComboBox(
            Id(:linkmode),
            Opt(:hstretch, :notify),
            _("link mode:"),
            ["passive", "active", "rr"]
          )
        ),
        Left(
          CheckBox(Id(:autoid), Opt(:notify), _("Auto Generate Node ID"), true)
        )
      )

      contents = VBox(
        HBox(hid),
        nodelist_table,
        iface_table,
        HBox(nid),
      )

      my_SetContents("communication", contents)

      UI.ChangeWidget(Id(:autoid), :Value, Cluster.autoid)
      UI.ChangeWidget(Id(:cluster_name), :Value, Cluster.cluster_name)

      UI.ChangeWidget(Id(:transport), :Value, Cluster.transport)
      UI.ChangeWidget(Id(:ip_version), :Value, Cluster.ip_version)

      UI.ChangeWidget(Id(:linkmode), :Value, Cluster.link_mode)

      # BNC#879596, check the corosync.conf format
      if Cluster.config_format == "corosync2"
        Popup.Message(_(" NOTICE: Detected old corosync2 configuration.\n Please reconfigure the node/interface list and confirm all other settings."))
        Cluster.config_format = "showed"
      elsif Cluster.config_format == "openais"
        Popup.Message(_(" NOTICE: Detected old(SLE11) openais/corosync configuration.\n Please reconfigure the node list and confirm all other settings."))
        Cluster.config_format = "showed"
      end

      nil
    end

    def fill_interface_entries
      current = 0

      table_items = _get_interface_table_items()

      current = UI.QueryWidget(:ifacelist, :CurrentItem).to_i
      current = 0 if current == nil
      current = table_items.size - 1 if current >= table_items.size

      UI.ChangeWidget(:ifacelist, :Items, table_items)
      UI.ChangeWidget(:ifacelist, :CurrentItem, current)

      nil
    end

    def fill_nodelist_entries
      current = 0

      table_items = _get_nodelist_table_items()

      current = UI.QueryWidget(:nodelist, :CurrentItem).to_i
      current = 0 if current == nil
      current = table_items.size - 1 if current >= table_items.size

      UI.ChangeWidget(:nodelist, :Items, table_items)
      UI.ChangeWidget(:nodelist, :CurrentItem, current)

      nil
    end

    def switch_totem_button(transport)
      if transport == "knet"
        UI.ChangeWidget(Id(:linkmode), :Enabled, true)

        UI.ChangeWidget(Id(:autoid), :Value, false)
        UI.ChangeWidget(Id(:autoid), :Enabled, false)
      else
        UI.ChangeWidget(Id(:linkmode), :Value, "passive")
        UI.ChangeWidget(Id(:linkmode), :Enabled, false)

        UI.ChangeWidget(Id(:autoid), :Enabled, true)
      end

      # For UDPU an interface section is not needed
      if transport == "udpu"
        UI.ChangeWidget(Id(:ifacelist), :Enabled, false)
        UI.ChangeWidget(Id(:ifacelist_add), :Enabled, false)
        UI.ChangeWidget(Id(:ifacelist_edit), :Enabled, false)
        UI.ChangeWidget(Id(:ifacelist_del), :Enabled, false)
      else
        UI.ChangeWidget(Id(:ifacelist), :Enabled, true)
        UI.ChangeWidget(Id(:ifacelist_add), :Enabled, true)
        UI.ChangeWidget(Id(:ifacelist_edit), :Enabled, true)
        UI.ChangeWidget(Id(:ifacelist_del), :Enabled, true)
      end

      if _has_ipv6_addr()
        UI.ChangeWidget(Id(:autoid), :Value, false)
        UI.ChangeWidget(Id(:autoid), :Enabled, false)
      end

      nil
    end

    def CommunicationDialog
      ret = nil

      CommunicationLayout()

      while true
        fill_nodelist_entries()
        fill_interface_entries()
        switch_totem_button(UI.QueryWidget(Id(:transport), :Value))

        transport = UI.QueryWidget(Id(:transport), :Value).to_s
        ip_version = UI.QueryWidget(Id(:ip_version), :Value).to_s

        ret = UI.UserInput

        if ret == :nodelist_add
          ret = nodelist_input_dialog({}, ip_version)

          next if ret == :cancel
          Cluster.node_list.push(ret)
        end

        if ret == :nodelist_edit
          current = 0
          current = UI.QueryWidget(:nodelist, :CurrentItem).to_i
          ret = nodelist_input_dialog(Cluster.node_list[current] || {}, ip_version)

          next if ret == :cancel
          Cluster.node_list[current] = ret
        end

        if ret == :nodelist_del
          current = 0
          current = UI.QueryWidget(:nodelist, :CurrentItem).to_i
          Cluster.node_list.delete_at(current)
        end

        if ret == :ifacelist_add
          ret = interface_input_dialog({}, transport)

          next if ret == :cancel
          Cluster.interface_list.push(ret)
        end

        if ret == :ifacelist_edit
          current = 0
          current = UI.QueryWidget(:ifacelist, :CurrentItem).to_i
          ret = interface_input_dialog(Cluster.interface_list[current] || {}, transport)

          next if ret == :cancel
          # Clear the interface_input_dialog support key in case not configured
          ["linknumber", "knet_transport", "knet_link_priority",
           "bindnetaddr", "mcastaddr", "mcastport"].each do |ele|
            Cluster.interface_list[current].delete(ele)
          end

          # Use merge! since not all parameters show in UI
          Cluster.interface_list[current].merge!(ret)
        end

        if ret == :ifacelist_del
          current = 0
          current = UI.QueryWidget(:ifacelist, :CurrentItem).to_i
          Cluster.interface_list.delete_at(current)
        end

        if ret == :next || ret == :back
          val = ValidateCommunication()
          if val == true
            SaveCommunication()
            break
          else
            ret = nil
            next
          end
        end

        if ret == :abort || ret == :cancel
          if ReallyAbort()
            return deep_copy(ret)
          else
            next
          end
        end

        if ret == :wizardTree
          ret = Convert.to_string(UI.QueryWidget(Id(:wizardTree), :CurrentItem))
        end

        if Builtins.contains(@DIALOG, Convert.to_string(ret))
          ret = Builtins.symbolof(Builtins.toterm(ret))
          val = ValidateCommunication()
          if val == true
            SaveCommunication()
            break
          else
            ret = nil
            Wizard.SelectTreeItem("communication")
            next
          end
        end

        Builtins.y2error("unexpected retcode: %1", ret)
      end

      deep_copy(ret)
    end

    def ValidateSecurity
      if Cluster.transport == "knet"
        if UI.QueryWidget(Id(:secauth), :Value)
          if UI.QueryWidget(Id(:crypto_hash), :Value) == "none"
            Popup.Message(_("Should use valid value of crypto hash to encrypt"))
            UI.SetFocus(:crypto_hash)
            return false
          end

          if UI.QueryWidget(Id(:crypto_cipher), :Value) == "none"
            Popup.Message(_("Should use valid value of crypto cipher to encrypt"))
            UI.SetFocus(:crypto_cipher)
            return false
          end
        end
      else
        if UI.QueryWidget(Id(:secauth), :Value)
          Popup.Message(_("Encrypted transmission is only supported for the knet transport"))
          UI.SetFocus(:secauth)
          return false
        end
      end

      true
    end

    def SaveSecurity
      if Cluster.transport == "knet"
        Cluster.secauth = Convert.to_boolean(UI.QueryWidget(Id(:secauth), :Value))
        Cluster.crypto_model = UI.QueryWidget(Id(:crypto_model), :Value).to_s
        Cluster.crypto_hash = UI.QueryWidget(Id(:crypto_hash), :Value).to_s
        Cluster.crypto_cipher = UI.QueryWidget(Id(:crypto_cipher), :Value).to_s
      else
        Cluster.secauth = false
        Cluster.crypto_model = "nss"
        Cluster.crypto_hash = "none"
        Cluster.crypto_cipher = "none"
      end

      nil
    end

    def heuristics_executables_input_dialog(name="", script="")
      ret = nil

      UI.OpenDialog(
        MarginBox(
          1,
          1,
          VBox(
            HBox(
            MinWidth(40, InputField(Id(:exec_name), _("Execute Name"), name)),
            HSpacing(1),
            MinWidth(100, InputField(Id(:exec_script), _("Execute Script"), script))
            ),
            VSpacing(1),
            Right(
              HBox(
                PushButton(Id(:ok), _("OK")),
                PushButton(Id(:cancel), _("Cancel"))
              )
            )
          )
        )
      )

      ret = UI.UserInput
      if ret == :ok
        ret = { UI.QueryWidget(:exec_name, :Value) => UI.QueryWidget(:exec_script, :Value) }
      end
      UI.CloseDialog

      deep_copy(ret)
    end

    def ValidateCorosyncQdevice
      if UI.QueryWidget(Id(:corosync_qdevice), :Value) == false
        return true
      end

      if UI.QueryWidget(Id(:qdevice_model), :Value) != "net"
        Popup.Message(_("The model basically defines the type of arbitrator, currently only net is support"))
        UI.SetFocus(:qdevice_model)
        return false
      end

      if !IP.Check(UI.QueryWidget(Id(:qdevice_host), :Value))
        Popup.Message(_("Qdevice host mush have a valid IP address"))
        UI.SetFocus(:qdevice_host)
        return false
      end

      if UI.QueryWidget(Id(:qdevice_port), :Value).to_i <= 0
        Popup.Message(_("The corosync qdevice port must be a positive integer"))
        UI.SetFocus(Id(:qdevice_port))
        return false
      end

      if !["lowest", "highest"].include?(UI.QueryWidget(Id(:qdevice_tie_breaker), :Value)) &&
        (UI.QueryWidget(Id(:qdevice_tie_breaker), :Value).to_i <= 0)
        Popup.Message(_("The tie breaker can be one of lowest, highest or a valid node id (number)"))
        UI.SetFocus(Id(:qdevice_tie_breaker))
        return false
      end

      if UI.QueryWidget(Id(:corosync_qdevice), :Value) && Cluster.node_list.size <= 0
        # Intent not return false since address is in another dialog.
        Popup.Message(_("Node addresses is required when enable corosync qdevice"))
      end

      if UI.QueryWidget(Id(:heuristics_mode), :Value) != "off"
        if UI.QueryWidget(Id(:heuristics_timeout), :Value).to_i <= 0
          Popup.Message(_("The qdevice heuristics timeout must be a positive integer"))
          UI.SetFocus(Id(:heuristics_timeout))
          return false
        end

        if UI.QueryWidget(Id(:heuristics_sync_timeout), :Value).to_i <= 0
          Popup.Message(_("The qdevice heuristics sync timeout must be a positive integer"))
          UI.SetFocus(Id(:heuristics_sync_timeout))
          return false
        end

        if UI.QueryWidget(Id(:heuristics_interval), :Value).to_i <= 0
          Popup.Message(_("The qdevice heuristics interval must be a positive integer"))
          UI.SetFocus(Id(:heuristics_interval))
          return false
        end

        if Cluster.heuristics_executables.size <= 0
          Popup.Message(_("The heuristics executable script must config"))
          return false
        end
      end

      true
    end

    def SaveCorosyncQdevice
      Cluster.corosync_qdevice = Convert.to_boolean(UI.QueryWidget(Id(:corosync_qdevice), :Value))

      Cluster.qdevice_model = UI.QueryWidget(Id(:qdevice_model), :Value)
      Cluster.qdevice_host = UI.QueryWidget(Id(:qdevice_host), :Value)
      Cluster.qdevice_port = UI.QueryWidget(Id(:qdevice_port), :Value).to_s
      Cluster.qdevice_tls = UI.QueryWidget(Id(:qdevice_tls), :Value)
      Cluster.qdevice_algorithm = UI.QueryWidget(Id(:qdevice_algorithm), :Value)
      Cluster.qdevice_tie_breaker = UI.QueryWidget(Id(:qdevice_tie_breaker), :Value)

      Cluster.heuristics_mode = UI.QueryWidget(Id(:heuristics_mode), :Value)
      Cluster.heuristics_timeout = UI.QueryWidget(Id(:heuristics_timeout), :Value).to_i
      Cluster.heuristics_sync_timeout = UI.QueryWidget(Id(:heuristics_sync_timeout), :Value).to_i
      Cluster.heuristics_interval = UI.QueryWidget(Id(:heuristics_interval), :Value).to_i

      nil
    end

    def CorosyncQdeviceLayout
      qdevice_section = VBox(
        Left(ComboBox(
          Id(:qdevice_model),
          Opt(:hstretch),
          _("Qdevice model:"),
          ["net"]
        ))
      )

      qdevice_net_section = VBox(
        HBox(
          Left(InputField(Id(:qdevice_host),Opt(:hstretch), _("Qnetd server host:"),"")),
          HSpacing(1),
          Left(InputField(Id(:qdevice_port),Opt(:hstretch), _("Qnetd server TCP port:"),"5403"))
        ),
        HBox(
          Left(ComboBox(
            Id(:qdevice_tls), Opt(:hstretch), _("TLS:"),
            ["off", "on", "required"]
          )),
          Left(ComboBox(Id(:qdevice_algorithm),Opt(:hstretch, :notify), _("Algorithm:"),["ffsplit"])),
          HSpacing(1),
          Left(InputField(Id(:qdevice_tie_breaker),Opt(:hstretch), _("Tie breaker:"),"lowest"))
        )
      )

      qdevice_heuristics_section = VBox(
        HBox(
          Left(ComboBox(
            Id(:heuristics_mode), Opt(:hstretch, :notify), _("Heuristics Mode:"),
            ["off", "on", "sync"]
          ))
        ),
        HBox(
          Left(InputField(Id(:heuristics_timeout),Opt(:hstretch), _("Heuristics Timeout(milliseconds):"),"5000")),
          HSpacing(1),
          Left(InputField(Id(:heuristics_sync_timeout),Opt(:hstretch), _("Heuristics Sync_timeout(milliseconds):"),"15000")),
          HSpacing(1),
          Left(InputField(Id(:heuristics_interval),Opt(:hstretch), _("Heuristics Interval(milliseconds):"),"30000")),
        ),
        VBox(
          Left(Label(_("Heuristics Executables:"))),
          Table(Id(:heuristics_executables), Header(_("Name"), _("Value")), []),
          Right(HBox(
            PushButton(Id(:executable_add), "Add"),
            PushButton(Id(:executable_del), "Del"),
            PushButton(Id(:executable_edit), "Edit"))
          )
        )
      )

      contents = VBox(
        VSpacing(1),
        CheckBoxFrame(
          Id(:corosync_qdevice),
          Opt(:hstretch, :notify),
          _("En&able Corosync Qdevice"),
          false,
          VBox(
            qdevice_section,
            qdevice_net_section,
            qdevice_heuristics_section,
          )
        ),
        VStretch()
      )

      my_SetContents("corosyncqdevice", contents)

      UI.ChangeWidget(Id(:corosync_qdevice), :Value, Cluster.corosync_qdevice)

      UI.ChangeWidget(Id(:qdevice_model), :Value, Cluster.qdevice_model)

      UI.ChangeWidget(Id(:qdevice_host), :Value, Cluster.qdevice_host)
      UI.ChangeWidget(Id(:qdevice_port), :Value, Cluster.qdevice_port)
      UI.ChangeWidget(Id(:qdevice_tls), :Value, Cluster.qdevice_tls)
      UI.ChangeWidget(Id(:qdevice_algorithm), :Value, Cluster.qdevice_algorithm)
      # As for now, ffsplit is only can be configuried withing Yast (sync with crmsh)
      if UI.QueryWidget(Id(:qdevice_algorithm), :Value) == "ffsplit"
        Cluster.qdevice_votes = "1"
      end
      UI.ChangeWidget(Id(:qdevice_tie_breaker), :Value, Cluster.qdevice_tie_breaker)

      UI.ChangeWidget(Id(:heuristics_mode), :Value, Cluster.heuristics_mode)
      UI.ChangeWidget(Id(:heuristics_timeout), :Value, Cluster.heuristics_timeout)
      UI.ChangeWidget(Id(:heuristics_sync_timeout), :Value, Cluster.heuristics_sync_timeout)
      UI.ChangeWidget(Id(:heuristics_interval), :Value, Cluster.heuristics_interval)

      nil
    end

    def UpdateQdeviceVotes
      is_ffsplit = UI.QueryWidget(Id(:qdevice_algorithm), :Value) == "ffsplit"

      if is_ffsplit
        UI.ChangeWidget(Id(:qdevice_votes), :Value, "1")
      end

      UI.ChangeWidget(Id(:qdevice_votes), :Enabled, !is_ffsplit)

      nil
    end

    def heuristics_switch
      if !UI.QueryWidget(Id(:heuristics_mode), :Value) ||
          UI.QueryWidget(Id(:heuristics_mode), :Value) == "off"
        disable = false
      else
        disable = true
      end

      UI.ChangeWidget(Id(:heuristics_timeout), :Enabled, disable)
      UI.ChangeWidget(Id(:heuristics_sync_timeout), :Enabled, disable)
      UI.ChangeWidget(Id(:heuristics_interval), :Enabled, disable)
      UI.ChangeWidget(Id(:heuristics_executables), :Enabled, disable)

      nil
    end

    def fill_qdevice_heuristics_executables
      items = []

      Cluster.heuristics_executables.each do |name, value|
        items.push(Item(Id(name.to_s), name.to_s, value.to_s))
      end

      UI.ChangeWidget(Id(:heuristics_executables), :Items, items)

      nil
    end

    def CorosyncQdeviceDialog
      ret = nil

      CorosyncQdeviceLayout()

      while true
        fill_qdevice_heuristics_executables
        heuristics_switch

        ret = UI.UserInput

        if ret == :corosync_qdevice
          if UI.QueryWidget(Id(:corosync_qdevice), :Value) == false
            next
          end
        end

        if ret == :heuristics_mode
          next
        end

        if ret == :executable_add
          ret = heuristics_executables_input_dialog()
          next if ret == :cancel
          Cluster.heuristics_executables.merge!(ret)
          next
        end

        if ret == :executable_edit
          exec_name = UI.QueryWidget(:heuristics_executables, :CurrentItem).to_s
          ret = heuristics_executables_input_dialog(exec_name,
                                                    Cluster.heuristics_executables[exec_name].to_s)
          next if ret == :cancel
          Cluster.heuristics_executables.delete(exec_name)
          Cluster.heuristics_executables[ret.keys()[0]] = ret.values()[0]
          next
        end

        if ret == :executable_del
          exec_name = UI.QueryWidget(:heuristics_executables, :CurrentItem).to_s
          Cluster.heuristics_executables.delete(exec_name)
          next
        end

        if ret == :next || ret == :back
          val = ValidateCorosyncQdevice()
          if val == true
            SaveCorosyncQdevice()
            break
          else
            ret = nil
            next
          end
        end

        if ret == :abort || ret == :cancel
          if ReallyAbort()
            return deep_copy(ret)
          else
            next
          end
        end

        if ret == :wizardTree
          ret = Convert.to_string(UI.QueryWidget(Id(:wizardTree), :CurrentItem))
        end

        if Builtins.contains(@DIALOG, Convert.to_string(ret))
          ret = Builtins.symbolof(Builtins.toterm(ret))
          val = ValidateCorosyncQdevice()
          if val == true
            SaveCorosyncQdevice()
            break
          else
            ret = nil
            Wizard.SelectTreeItem("corosyncqdevice")
            next
          end
        end

        Builtins.y2error("unexpected retcode: %1", ret)
      end
      deep_copy(ret)
    end

    def switch_secauth_button(enable)
      if enable
        if UI.QueryWidget(Id(:crypto_hash), :Value) == "none"
          UI.ChangeWidget(Id(:crypto_hash), :Value, "sha256")
        end

        if UI.QueryWidget(Id(:crypto_cipher), :Value) == "none"
          UI.ChangeWidget(Id(:crypto_cipher), :Value, "aes256")
        end
      else
        UI.ChangeWidget(Id(:crypto_hash), :Value, "none")
        UI.ChangeWidget(Id(:crypto_cipher), :Value, "none")
      end
    end

    def SecurityDialog
      ret = nil

      contents = VBox(
        VSpacing(1),
        CheckBoxFrame(
          Id(:secauth),
          Opt(:hstretch, :notify),
          _("Enable Security Auth"),
          true,
          VBox(
            HBox(
              HSpacing(20),
              Left(ComboBox(
                Id(:crypto_model), Opt(:hstretch, :notify), _("Crypto Model:"),
                ["nss", "openssl"]
              )),
              HSpacing(5),
              Left(ComboBox(
                Id(:crypto_hash), Opt(:hstretch, :notify), _("Crypto Hash:"),
                ["sha256", "sha1", "sha384", "sha512", "md5", "none"]
              )),
              HSpacing(5),
              Left(ComboBox(
                Id(:crypto_cipher), Opt(:hstretch, :notify), _("Crypto Cipher:"),
                ["aes256", "aes192", "aes128", "3des", "none"]
              )),
              HSpacing(20),
            ),
            Label(
              _(
                "For a newly created cluster, push the button below to generate /etc/corosync/authkey."
              )
            ),
            Label(
              _(
                "To join an existing cluster, please copy /etc/corosync/authkey from other nodes manually."
              )
            ),
            PushButton(Id(:genf), Opt(:notify), "Generate Auth Key File")
          )
        ),
        VStretch()
      )

      my_SetContents("security", contents)

      UI.ChangeWidget(Id(:secauth), :Value, Cluster.secauth)
      UI.ChangeWidget(Id(:crypto_model), :Value, Cluster.crypto_model)
      UI.ChangeWidget(Id(:crypto_hash), :Value, Cluster.crypto_hash)
      UI.ChangeWidget(Id(:crypto_cipher), :Value, Cluster.crypto_cipher)

      while true
        switch_secauth_button(UI.QueryWidget(Id(:secauth), :Value))

        ret = UI.UserInput

        if ret == :genf
          result = {}
          result = Convert.to_map(
            SCR.Execute(
              path(".target.bash_output"),
              "/usr/sbin/corosync-keygen -l"
            )
          )
          if Ops.get_integer(result, "exit", -1) != 0
            Popup.Message(_("Failed to create /etc/corosync/authkey"))
          else
            Popup.Message(_("Create /etc/corosync/authkey succeeded"))
          end
          next
        end

        if ret == :secauth || ret == :crypto_model || ret == :crypto_cipher || ret == :crypto_hash
          if UI.QueryWidget(Id(:secauth), :Value) == true
            next
          end
        end

        if ret == :next || ret == :back
          val = ValidateSecurity()
          if val == true
            SaveSecurity()
            break
          else
            ret = nil
            next
          end
        end

        if ret == :abort || ret == :cancel
          if ReallyAbort()
            return deep_copy(ret)
          else
            next
          end
        end

        if ret == :wizardTree
          ret = Convert.to_string(UI.QueryWidget(Id(:wizardTree), :CurrentItem))
        end

        if Builtins.contains(@DIALOG, Convert.to_string(ret))
          ret = Builtins.symbolof(Builtins.toterm(ret))
          val = ValidateSecurity()
          if val == true
            SaveSecurity()
            break
          else
            ret = nil
            Wizard.SelectTreeItem("security")
            next
          end
        end

        Builtins.y2error("unexpected retcode: %1", ret)
      end
      deep_copy(ret)
    end

    def ValidateService
      true
    end

    def UpdateServiceStatus
      ret_pacemaker = 0
      ret_qdevice = 0
      ret_pacemaker = Service.Status("pacemaker")
      if Cluster.corosync_qdevice && ret_pacemaker == 0
        ret_qdevice = Service.Status("corosync-qdevice")
        # corosync-qdevice stop/start
        if ret_qdevice == 0
          UI.ChangeWidget(Id(:status_qdevice), :Value, _("Running"))
          UI.ChangeWidget(Id("start_qdevice_now"), :Enabled, false)
          UI.ChangeWidget(Id("stop_qdevice_now"), :Enabled, true)
        else
          UI.ChangeWidget(Id(:status_qdevice), :Value, _("Not running"))
          UI.ChangeWidget(Id("start_qdevice_now"), :Enabled, true)
          UI.ChangeWidget(Id("stop_qdevice_now"), :Enabled, false)
        end
      else
        UI.ChangeWidget(Id(:status_qdevice), :Value, _("Not configured"))
        UI.ChangeWidget(Id("start_qdevice_now"), :Enabled, false)
        UI.ChangeWidget(Id("stop_qdevice_now"), :Enabled, false)
      end
      # pacemaker&corosync stop/start
      if ret_pacemaker == 0
        UI.ChangeWidget(Id(:status), :Value, _("Running"))
        UI.ChangeWidget(Id("start_now"), :Enabled, false)
        UI.ChangeWidget(Id("stop_now"), :Enabled, true)
      else
        UI.ChangeWidget(Id(:status), :Value, _("Not running"))
        UI.ChangeWidget(Id("start_now"), :Enabled, true)
        UI.ChangeWidget(Id("stop_now"), :Enabled, false)
      end

      ret_qdevice_booting = true
      if Cluster.corosync_qdevice
        ret_qdevice_booting = Service.Enabled("corosync-qdevice")
      end
      if Service.Enabled("pacemaker") && ret_qdevice_booting
        UI.ChangeWidget(Id(:status_booting), :Value, _("Enabling"))
        UI.ChangeWidget(Id("on"), :Enabled, false)
        UI.ChangeWidget(Id("off"), :Enabled, true)
      else
        UI.ChangeWidget(Id(:status_booting), :Value, _("Disabling"))
        UI.ChangeWidget(Id("on"), :Enabled, true)
        UI.ChangeWidget(Id("off"), :Enabled, false)
      end

      nil
    end

    def ServiceDialog
      ret = nil


      firewall_widget = CWMFirewallInterfaces.CreateOpenFirewallWidget(
        {
          # cluster is the  name of /usr/lib/firewalld.d/services/cluster.xml
          "services"        => [
            "cluster"
          ],
          "display_details" => true
        }
      )
      Builtins.y2milestone("%1", firewall_widget)
      firewall_layout = Ops.get_term(firewall_widget, "custom_widget", VBox())


      contents = VBox(
        VSpacing(1),
        Frame(
          _("Cluster start at booting time enable/disable"),
          Left(
            VBox(
              Left(
                HBox(
                  HSpacing(1),
                  Label(_("Current Status: ")),
                  Label(Id(:status_booting), _("Enabling")),
                  ReplacePoint(Id("status_rp"), Empty())
                )
              ),
              Left(
                HBox(
                  HSpacing(1),
                  HBox(
                    PushButton(Id("on"), _("Enable cluster")),
                    PushButton(Id("off"), _("Disable cluster"))
                  )
                )
              )
            )
          )
        ),

        VSpacing(1),
        Frame(
          _("Pacemaker and corosync start/stop"),
          Left(
            VBox(
              Left(
                HBox(
                  HSpacing(1),
                  Label(_("Current Status: ")),
                  Label(Id(:status), _("Running")),
                  ReplacePoint(Id("status_rp"), Empty())
                )
              ),
              Left(
                HBox(
                  HSpacing(1),
                  HBox(
                    PushButton(Id("start_now"), _("Start Now")),
                    PushButton(Id("stop_now"), _("Stop Now"))
                  )
                )
              )
            )
          )
        ),
        VSpacing(1),
        Frame(
          _("corosync-qdevice start/stop"),
          Left(
            VBox(
              Left(
                HBox(
                  HSpacing(1),
                  Label(_("Current Status: ")),
                  Label(Id(:status_qdevice), _("Running")),
                  ReplacePoint(Id("status_rp_qdevice"), Empty())
                )
              ),
              Left(
                HBox(
                  HSpacing(1),
                  HBox(
                    PushButton(Id("start_qdevice_now"), _("Start Now")),
                    PushButton(Id("stop_qdevice_now"), _("Stop Now"))
                  )
                )
              )
            )
          )
        ),
        VSpacing(1),
        firewall_layout,
        VStretch()
      )


      my_SetContents("service", contents)

      event = {}
      errormsg = "See 'journalctl -xn' for details."
      CWMFirewallInterfaces.OpenFirewallInit(firewall_widget, "")
      while true
        UpdateServiceStatus()
        # add event
        event = UI.WaitForEvent
        ret = Ops.get(event, "ID")

        if ret == "on"
          Service.Enable("pacemaker")
          if Cluster.corosync_qdevice
            Service.Enable("corosync-qdevice")
          end
          next
        end

        if ret == "off"
          Service.Disable("pacemaker")
          if Cluster.corosync_qdevice
            Service.Disable("corosync-qdevice")
          end
          next
        end

        # pacemaker will start corosync automatically.
        if ret == "start_now"
          Cluster.save_csync2_conf
          Cluster.SaveClusterConfig
          # BNC#872652 , add more info about error message
          Report.Error(Service.Error + errormsg) if !Service.Start("pacemaker")
          next
        end
        # corosync-qdevice start
        if ret == "start_qdevice_now"
            Cluster.save_csync2_conf
            Cluster.SaveClusterConfig
            # reload the corosync.conf before starting qdevice within already started corosync
            %x(corosync-cfgtool -R)
            sleep(1)
            Report.Error(Service.Error + errormsg) if !Service.Start("corosync-qdevice")
            next
        end

        # pacemaker&corosync stop
        if ret == "stop_now"
          # BNC#874563,stop pacemaker could stop corosync since BNC#872651 is fixed
          # In bnc#1144200, the patch is dropped in corosync, so stop pacemaker not working
          Report.Error(Service.Error + errormsg) if !Service.Stop("corosync")
          next
        end
        # corosync-qdevice stop
        if ret == "stop_qdevice_now"
          Report.Error(Service.Error + errormsg) if !Service.Stop("corosync-qdevice")
          next
        end

        if ret == :next || ret == :back
          val = ValidateService()
          if val == true
            CWMFirewallInterfaces.OpenFirewallStore(firewall_widget, "", event)
            break
          else
            ret = nil
            next
          end
        end

        if ret == :abort || ret == :cancel
          if ReallyAbort()
            return deep_copy(ret)
          else
            next
          end
        end

        if ret == :wizardTree
          ret = Convert.to_string(UI.QueryWidget(Id(:wizardTree), :CurrentItem))
        end

        if Builtins.contains(@DIALOG, Convert.to_string(ret))
          ret = Builtins.symbolof(Builtins.toterm(ret))
          val = ValidateService()
          if val == true
            break
          else
            ret = nil
            Wizard.SelectTreeItem("service")
            next
          end
        end

        CWMFirewallInterfaces.OpenFirewallHandle(firewall_widget, "", event)

        Builtins.y2error("unexpected retcode: %1", ret)
      end
      deep_copy(ret)
    end


    def csync2_layout
      VBox(
        Opt(:hvstretch),
        HBox(
          Frame(
            _("Sync Host"),
            VBox(
              SelectionBox(Id(:host_box), ""),
              HBox(
                PushButton(Id(:host_add), _("Add")),
                PushButton(Id(:host_del), _("Del")),
                PushButton(Id(:host_edit), _("Edit"))
              )
            )
          ),
          HSpacing(),
          Frame(
            _("Sync File"),
            VBox(
              SelectionBox(Id(:include_box), ""),
              HBox(
                PushButton(Id(:include_add), _("Add")),
                PushButton(Id(:include_del), _("Del")),
                PushButton(Id(:include_edit), _("Edit")),
                PushButton(Id(:include_suggest), _("Add Suggested Files"))
              )
            )
          )
        ),
        HBox(
          PushButton(
            Id(:generate_key),
            Opt(:hstretch),
            _("Generate Pre-Shared-Keys")
          ),
          PushButton(Id(:csync2_switch), Opt(:hstretch), "")
        )
      )
    end


    # return 1 if csync2 is not installed well
    # return 2 if csync2 is OFF or csync2 is blocked by firewall
    # return 3 if csync2 is ON
    def csync2_status
      csync2_socket = Yast2::Systemd::Socket.find(@csync2_package)

      if !csync2_socket
        y2error("csync2.socket not found.")
        return 1
      end

      if !csync2_socket.enabled?
        y2debug("csync2.socket is disabled.")
        return 2
      end

      #check the firewall whether csync2 port was blocked.
      begin
        firewalld_cluster = firewalld.find_service("cluster")
        tcp_ports = firewalld_cluster.tcp_ports
      rescue Y2Firewall::Firewalld::Service::NotFound
        y2debug("Firewalld service not found.")
        return 3
      end

      tcp_ports.include?(@csync2_port) ? 3 : 2
    end

    def csync2_turn_off
      csync2_socket = nil
      csync2_socket = Yast2::Systemd::Socket.find(@csync2_package)

      if !csync2_socket
        y2error("csync2.socket is missing.")
        return nil
      end

      csync2_socket.stop
      csync2_socket.disable
      y2debug("Stop and disable csync2.socket.")

      begin
        fwd_cluster = firewalld.find_service("cluster")
        tcp_ports = fwd_cluster.tcp_ports
      rescue Y2Firewall::Firewalld::Service::NotFound
        tcp_ports = []
      end

      tcp_ports.delete(@csync2_port) if tcp_ports.include?(@csync2_port)

      begin
        Y2Firewall::Firewalld::Service.modify_ports(name: "cluster", tcp_ports: tcp_ports)
      rescue Y2Firewall::Firewalld::Service::NotFound
        y2error("Firewalld 'cluster' service is not available.")
      end

      nil
    end

    def csync2_turn_on
      csync2_socket = nil
      csync2_socket = Yast2::Systemd::Socket.find(@csync2_package)

      if !csync2_socket
        y2error("csync2.socket is missing.")
        return nil
      end

      csync2_socket.start
      csync2_socket.enable
      y2debug("Start and enable csync2.socket.")

      begin
        fwd_cluster = firewalld.find_service("cluster")
        tcp_ports = fwd_cluster.tcp_ports
      rescue Y2Firewall::Firewalld::Service::NotFound
        tcp_ports = []
      end

      tcp_ports << @csync2_port unless tcp_ports.include?(@csync2_port)

      begin
        Y2Firewall::Firewalld::Service.modify_ports(name: "cluster", tcp_ports: tcp_ports)
      rescue Y2Firewall::Firewalld::Service::NotFound
        y2error("Firewalld 'cluster' service is not available.")
      end

      nil
    end

    def fill_csync_entries
      i = 0
      ret = 0
      current = 0
      items = []

      # remove duplicated elements
      Cluster.csync2_host = Ops.add(Cluster.csync2_host, [])
      Cluster.csync2_include = Ops.add(Cluster.csync2_include, [])

      i = 0
      items = []
      Builtins.foreach(Cluster.csync2_host) do |value|
        items = Builtins.add(items, Item(Id(i), value))
        i = Ops.add(i, 1)
      end
      current = Convert.to_integer(UI.QueryWidget(:host_box, :CurrentItem))
      current = 0 if current == nil
      current = Ops.subtract(i, 1) if Ops.greater_or_equal(current, i)
      UI.ChangeWidget(:host_box, :Items, items)
      UI.ChangeWidget(:host_box, :CurrentItem, current)

      i = 0
      items = []
      Builtins.foreach(Cluster.csync2_include) do |value|
        items = Builtins.add(items, Item(Id(i), value))
        i = Ops.add(i, 1)
      end
      current = Convert.to_integer(UI.QueryWidget(:include_box, :CurrentItem))
      current = 0 if current == nil
      current = Ops.subtract(i, 1) if Ops.greater_or_equal(current, i)
      UI.ChangeWidget(:include_box, :Items, items)
      UI.ChangeWidget(:include_box, :CurrentItem, current)

      ret = csync2_status
      UI.ChangeWidget(Id(:csync2_switch), :Enabled, ret != 1)
      if ret == 1
        UI.ChangeWidget(Id(:csync2_switch), :Label, _("Csync2 Status Unknown"))
      end
      if ret == 2
        UI.ChangeWidget(Id(:csync2_switch), :Label, _("Turn csync2 ON"))
      end
      if ret == 3
        UI.ChangeWidget(Id(:csync2_switch), :Label, _("Turn csync2 OFF"))
      end

      nil
    end


    def Csync2Dialog
      ret = nil

      my_SetContents("csync2", csync2_layout)


      while true
        fill_csync_entries

        ret = UI.UserInput

        if ret == :abort || ret == :cancel
          break if ReallyAbort()
          next
        end

        break if ret == :next || ret == :back

        if ret == :wizardTree
          ret = Convert.to_string(UI.QueryWidget(Id(:wizardTree), :CurrentItem))
        end

        if ret == :host_add
          ret = text_input_dialog(_("Enter a hostname"), "")
          next if ret == :cancel
          Cluster.csync2_host = Builtins.add(
            Cluster.csync2_host,
            Convert.to_string(ret)
          )
        end

        if ret == :host_edit
          current = 0

          current = Convert.to_integer(UI.QueryWidget(:host_box, :CurrentItem))
          ret = text_input_dialog(
            _("Edit the hostname"),
            Ops.get(Cluster.csync2_host, current, "")
          )
          next if ret == :cancel
          Ops.set(Cluster.csync2_host, current, Convert.to_string(ret))
        end

        if ret == :host_del
          current = 0
          current = Convert.to_integer(UI.QueryWidget(:host_box, :CurrentItem))
          Cluster.csync2_host = Builtins.remove(Cluster.csync2_host, current)
        end

        if ret == :include_add
          ret = text_input_dialog(_("Enter a filename to synchronize"), "")
          next if ret == :cancel
          Cluster.csync2_include = Builtins.add(
            Cluster.csync2_include,
            Convert.to_string(ret)
          )
        end

        if ret == :include_edit
          current = 0

          current = Convert.to_integer(
            UI.QueryWidget(:include_box, :CurrentItem)
          )
          ret = text_input_dialog(
            _("Edit the filename"),
            Ops.get(Cluster.csync2_include, current, "")
          )
          next if ret == :cancel
          Ops.set(Cluster.csync2_include, current, Convert.to_string(ret))
        end

        if ret == :include_del
          current = 0
          current = Convert.to_integer(
            UI.QueryWidget(:include_box, :CurrentItem)
          )
          Cluster.csync2_include = Builtins.remove(
            Cluster.csync2_include,
            current
          )
        end

        if ret == :include_suggest
          Cluster.csync2_include = Ops.add(
            Cluster.csync2_include,
            @csync2_suggest_files
          )
        end

        if ret == :generate_key
          key_file = Cluster.csync2_key_file

          # key file exist
          if Ops.greater_than(SCR.Read(path(".target.size"), key_file), 0)
            if !Popup.YesNo(
                Builtins.sformat(
                  _("Key file %1 already exist.\nDo you want to overwrite it?"),
                  key_file
                )
              )
              next
            end

            # remove exist key file
            if SCR.Execute(path(".target.remove"), key_file) == false
              Popup.Message(
                Builtins.sformat(_("Delete key file %1 failed."), key_file)
              )
              next
            end
          end

          # generate key file
          ret = SCR.Execute(
            path(".target.bash"),
            Builtins.sformat("csync2 -k %1", key_file)
          )
          if ret == 0
            Popup.Message(
              Builtins.sformat(
                _(
                  "Key file %1 is generated.\nClicking \"Add Suggested Files\" button adds it to sync list."
                ),
                key_file
              )
            )
          else
            Popup.Message(_("Key generation failed."))
          end
        end

        if ret == :csync2_switch
          label = ""
          label = Convert.to_string(UI.QueryWidget(:csync2_switch, :Label))
          csync2_turn_off if Builtins.issubstring(label, "OFF")
          csync2_turn_on if Builtins.issubstring(label, "ON")
        end

        if Builtins.contains(@DIALOG, Convert.to_string(ret))
          ret = Builtins.symbolof(Builtins.toterm(ret))
          #SaveCsync2();
          break
        else
          Wizard.SelectTreeItem("csync2")
          next
        end
      end

      deep_copy(ret)
    end

    def conntrack_layout
      result = {}

      result = Convert.to_map(
        SCR.Execute(
          path(".target.bash_output"),
          "/sbin/ip a | grep MULTICAST | grep 'state UP' | awk '{print $2}' | awk -F: '{print $1}'"
        )
      )

      if Builtins.size(Ops.get_string(result, "stdout", "")) != 0
        infs = Builtins.splitstring(Ops.get_string(result, "stdout", ""), "\n")
        Builtins.foreach(infs) do |inf|
          result = Convert.to_map(
            SCR.Execute(
              path(".target.bash_output"),
              Ops.add(
                Ops.add("/sbin/ip addr show scope global dev ", inf),
                " | grep inet | awk '{print $2}' | awk -F/ '{print $1}'"
              )
            )
          )
          ip = Ops.get(
            Builtins.splitstring(Ops.get_string(result, "stdout", ""), "\n"),
            0,
            ""
          )
          if Builtins.size(ip) != 0
            @usable_interface = Builtins.add(@usable_interface, inf)
          end
        end
      end

      VBox(
        Opt(:hvstretch),
        Label(
          Id(:conntrack_explain),
          Opt(:hstretch),
          _(
            "Conntrackd is a daemon which helps to duplicate firewall status between cluster nodes.\n" +
              "YaST can help to configure some basic aspects of conntrackd.\n" +
              "You need to start it with the ocf:heartbeat:conntrackd."
          )
        ),
        HBox(
          Opt(),
          ComboBox(
            Id(:conntrack_bindinf),
            Opt(:hstretch, :notify),
            _("Dedicated Interface:"),
            Builtins.toset(@usable_interface)
          ),
          Label(Id(:conntrack_bindip), Opt(:hstretch), _("IP:"))
        ),
        InputField(Id(:conntrack_addr), Opt(:hstretch), _("Multicast Address:")),
        InputField(Id(:conntrack_group), Opt(:hstretch), _("Group Number:")),
        PushButton(
          Id(:conntrack_generate),
          Opt(:hstretch),
          _("Generate /etc/conntrackd/conntrackd.conf")
        )
      )
    end

    def fill_conntrack_entries
      value = ""
      value = Convert.to_string(UI.QueryWidget(:conntrack_addr, :Value))
      if value == ""
        value = Convert.to_string(
          SCR.Read(path(".sysconfig.conntrackd.CONNTRACK_ADDR"))
        )
        value = "225.0.0.50" if Builtins.size(value) == 0
        UI.ChangeWidget(:conntrack_addr, :Value, value)
      end
      value = Convert.to_string(UI.QueryWidget(:conntrack_group, :Value))
      if value == ""
        value = Convert.to_string(
          SCR.Read(path(".sysconfig.conntrackd.CONNTRACK_GROUP"))
        )
        value = "3780" if value == ""
        UI.ChangeWidget(:conntrack_group, :Value, value)
      end
      value = Convert.to_string(
        SCR.Read(path(".sysconfig.conntrackd.CONNTRACK_INTERFACE"))
      )
      if value != ""
        if Builtins.contains(@usable_interface, value)
          UI.ChangeWidget(:conntrack_bindinf, :Value, value)
        end
      end
      qr = Convert.to_string(UI.QueryWidget(:conntrack_bindinf, :Value))
      ip = ""
      if qr != ""
        result = {}
        result = Convert.to_map(
          SCR.Execute(
            path(".target.bash_output"),
            Ops.add(
              Ops.add("/sbin/ip addr show scope global dev ", qr),
              " | grep inet | awk '{print $2}' | awk -F/ '{print $1}'"
            )
          )
        )
        ip = Ops.get(
          Builtins.splitstring(Ops.get_string(result, "stdout", ""), "\n"),
          0,
          ""
        )
      end
      UI.ChangeWidget(:conntrack_bindip, :Label, Ops.add("IP: ", ip))

      nil
    end

    def VerifyConntrackdConf
      if IP.Check(
          Convert.to_string(UI.QueryWidget(Id(:conntrack_addr), :Value))
        ) == false
        Popup.Message(_("The Multicast Address has to be fulfilled"))
        UI.SetFocus(:conntrack_addr)
        return false
      end
      if !Builtins.regexpmatch(
          Convert.to_string(UI.QueryWidget(Id(:conntrack_group), :Value)),
          "^[0-9]+$"
        )
        Popup.Message(_("The Group Number must be a positive integer"))
        UI.SetFocus(Id(:conntrack_group))
        return false
      end
      true
    end

    def ConntrackDialog
      ret = nil

      my_SetContents("conntrack", conntrack_layout)

      fill_conntrack_entries
      while true
        ret = UI.UserInput

        if ret == :abort || ret == :cancel
          break if ReallyAbort()
          next
        end

        if ret == :next || ret == :back
          value = ""
          value = Convert.to_string(UI.QueryWidget(:conntrack_addr, :Value))
          if value != ""
            SCR.Write(path(".sysconfig.conntrackd.CONNTRACK_ADDR"), value)
          end
          value = Convert.to_string(UI.QueryWidget(:conntrack_group, :Value))
          if value != ""
            SCR.Write(path(".sysconfig.conntrackd.CONNTRACK_GROUP"), value)
          end
          value = Convert.to_string(UI.QueryWidget(:conntrack_bindinf, :Value))
          if value != ""
            SCR.Write(path(".sysconfig.conntrackd.CONNTRACK_INTERFACE"), value)
          end
          break
        end

        if ret == :wizardTree
          ret = Convert.to_string(UI.QueryWidget(Id(:wizardTree), :CurrentItem))
        end

        if ret == :conntrack_bindinf
          qr = Convert.to_string(UI.QueryWidget(:conntrack_bindinf, :Value))
          ip = ""
          if qr != ""
            result = {}
            result = Convert.to_map(
              SCR.Execute(
                path(".target.bash_output"),
                Ops.add(
                  Ops.add("/sbin/ip addr show scope global dev ", qr),
                  " | grep inet | awk '{print $2}' | awk -F/ '{print $1}'"
                )
              )
            )
            ip = Ops.get(
              Builtins.splitstring(Ops.get_string(result, "stdout", ""), "\n"),
              0,
              ""
            )
          end
          UI.ChangeWidget(:conntrack_bindip, :Label, Ops.add("IP: ", ip))
          next
        end

        if ret == :conntrack_generate
          next if !VerifyConntrackdConf()
          addr = Convert.to_string(UI.QueryWidget(:conntrack_addr, :Value))
          group = Convert.to_string(UI.QueryWidget(:conntrack_group, :Value))
          inf = Convert.to_string(UI.QueryWidget(:conntrack_bindinf, :Value))
          ip = ""
          if inf != ""
            result = {}
            result = Convert.to_map(
              SCR.Execute(
                path(".target.bash_output"),
                Ops.add(
                  Ops.add("/sbin/ip addr show scope global dev ", inf),
                  " | grep inet | awk '{print $2}' | awk -F/ '{print $1}'"
                )
              )
            )
            ip = Ops.get(
              Builtins.splitstring(Ops.get_string(result, "stdout", ""), "\n"),
              0,
              ""
            )
          end

          fc_template = "Sync {\n" +
            "\tMode FTFW {\n" +
            "\t}\n" +
            "\tMulticast {\n" +
            "\t\tIPv4_address %1\n" +
            "\t\tGroup %2\n" +
            "\t\tIPv4_interface %3\n" +
            "\t\tInterface %4\n" +
            "\t\tSndSocketBuffer 1249280\n" +
            "\t\tRcvSocketBuffer 1249280\n" +
            "\t\tChecksum on\n" +
            "\t}\n" +
            "}\n" +
            "General {\n" +
            "\tNice -20\n" +
            "\tHashSize 32768\n" +
            "\tHashLimit 131072\n" +
            "\tLogFile on\n" +
            "\tLockFile /var/lock/conntrack.lock\n" +
            "\tUNIX {\n" +
            "\t\tPath /var/run/conntrackd.ctl\n" +
            "\t\tBacklog 20\n" +
            "\t}\n" +
            "\tNetlinkBufferSize 2097152\n" +
            "\tNetlinkBufferSizeMaxGrowth 8388608\n" +
            "\tFilter From Userspace {\n" +
            "\t\tProtocol Accept {\n" +
            "\t\t\tTCP\n" +
            "\t\t\tSCTP\n" +
            "\t\t\tDCCP\n" +
            "\t\t}\n" +
            "\t\tAddress Ignore {\n" +
            "\t\t\tIPv4_address 127.0.0.1\n" +
            "\t\t\tIPv4_address %5\n" +
            "\t\t}\n" +
            "\t}\n" +
            "}"
          fc = Builtins.sformat(fc_template, addr, group, ip, inf, ip)

          SCR.Execute(path(".target.bash_output"), "mkdir -p /etc/conntrackd")
          SCR.Execute(
            path(".target.bash_output"),
            "mv /etc/conntrackd/conntrackd.conf /etc/conntrackd/conntrackd.conf.YaST2bak"
          )
          SCR.Execute(
            path(".target.bash_output"),
            Ops.add(
              Ops.add("echo \"", fc),
              "\" > /etc/conntrackd/conntrackd.conf.YaST2"
            )
          )
          SCR.Execute(
            path(".target.bash_output"),
            "mv /etc/conntrackd/conntrackd.conf.YaST2 /etc/conntrackd/conntrackd.conf"
          )
          Popup.Message("Generated /etc/conntrackd/conntrackd.conf")
          next
        end

        if Builtins.contains(@DIALOG, Convert.to_string(ret))
          ret = Builtins.symbolof(Builtins.toterm(ret))
          break
        else
          Wizard.SelectTreeItem("conntrack")
          next
        end
      end
      deep_copy(ret)
    end

  private

    # Convenience for returning a Y2Firewall::Firewalld singleton instance.
    #
    # @return [Y2Firewall::Firewalld] singleton instance
    def firewalld
      Y2Firewall::Firewalld.instance
    end

  end
end
