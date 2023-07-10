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
        "/etc/modules-load.d/watchdog.conf",
        "/etc/crm/crm.conf",
        "/etc/crm/profiles.yml"
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

    def _has_ipfamily_addr(version="ipv6")
      has_ip = false

      if not Cluster.node_list.empty?
        Cluster.node_list.each do |node|
          node.default = []
          iplist = node["IPs"]

          iplist.each do |ip|
            if version == "ipv4"
              if IP.Check4(ip)
                has_ip = true
                break
              end
            else
              if IP.Check6(ip)
                has_ip = true
                break
              end
            end
          end # end iplist loop
        end # end node loop
      end # end node_list check

      if not Cluster.interface_list.empty?
        Cluster.interface_list.each do |iface|
          ["bindnetaddr", "mcastaddr"].each do |ele|
            if iface.has_key?(ele)
              if version == "ipv4"
                if IP.Check4(iface[ele])
                  has_ip = true
                  break
                end
              else
                if IP.Check6(iface[ele])
                  has_ip = true
                  break
                end
              end
            end
          end
        end # end interface loop
      end # end interface_list check

      has_ip
    end

    # return `cancel or a string
    def text_input_dialog(title, value)
      ret = nil

      UI.OpenDialog(
        MarginBox(
          1,
          1,
          VBox(
            MinWidth(50, InputField(Id(:text), title, value)),
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

    def get_free_nodeid()
      exist_id_list = []
      Cluster.node_list.each do |node|
        if !node["nodeid"].empty?
          exist_id_list << node["nodeid"]
        end
      end
      existing_ids = exist_id_list.to_set
      free_nodeid = 1
      while existing_ids.include?(free_nodeid.to_s)
        free_nodeid += 1
      end
      free_nodeid
    end

    def enable_widgets(enabled, *widget_ids)
      widget_ids.each do |widget_id|
        UI.ChangeWidget(Id(widget_id), :Enabled, enabled)
      end
    end

    def switch_iplist_button(iplist=[])
      haveip = !iplist.empty?

      UI.ChangeWidget(Id(:ip_add), :Enabled, true)
      enable_widgets(haveip, :ip_edit, :ip_del)

      nil
    end

    def switch_interface_button(transport, link_mode="passive")
      knet = transport == "knet"
      udp = transport == "udp"
      udpu = transport == "udpu"
      enable_widgets(knet, :linknumber, :knet_transport)
      enable_widgets(knet && link_mode == "passive", :knet_link_priority)
      enable_widgets(udp, :bindnetaddr, :mcastaddr, :mcastport)
      enable_widgets(udpu, :mcastport)

      nil
    end

    def switch_nodelist_button(nodelist=[])
      has_node = !nodelist.empty?

      UI.ChangeWidget(Id(:nodelist_add), :Enabled, true)
      enable_widgets(has_node, :nodelist_edit, :nodelist_del)

      nil
    end

    def switch_interface_list_button(interface_list=[])
      has_interface = !interface_list.empty?

      UI.ChangeWidget(Id(:ifacelist_add), :Enabled, true)
      enable_widgets(has_interface, :ifacelist_edit, :ifacelist_del)

      nil
    end

    def nodelist_input_dialog(value={}, transport = "knet", ip_version="ipv6-4", up_level_current=nil)
      value.default = ""
      if value["nodeid"].empty?
        nodeid = get_free_nodeid().to_s
      else
        nodeid = value["nodeid"]
      end
      orig_node_name = value["name"]

      UI.OpenDialog(
        MarginBox(
          1,
          1,
          VBox(
            HBox(
            MinWidth(20, InputField(Id(:mynodeid), Opt(:hstretch), _("Node ID:"), nodeid)),
            HSpacing(1),
            MinWidth(40, InputField(Id(:mynodename), Opt(:hstretch), _("Node Name:"), value["name"])),
            ),
            VSpacing(1),
            VBox(
              Opt(:hvstretch),
              MinSize(20, 12,
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
          ret = text_input_dialog(_("Add an IP address"), "")
          next if ret == :cancel || ret.empty?
          if !validate_ip(ret)
            next
          else
            _list = iplist.dup
            _list.push(ret)
            if !validate_ip_list(_list, transport)
              next
            end
          end
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
          if !validate_ip(ret, nodeid)
            next
          else
            _list = iplist.dup
            _list[current] = ret.to_s
            if !validate_ip_list(_list, transport)
              next
            end
          end
          if ret.empty?
            iplist.delete_at(current)
          else
            iplist[current] = ret.to_s
          end
        end

        if ret == :ip_del
          current = 0
          current = UI.QueryWidget(:iplist_table, :CurrentItem).to_i
          iplist.delete_at(current)
        end

        if ret == :ok
          if iplist.empty?
            Popup.Message(_("At least one ring/IP has to be fulfilled"))
            UI.SetFocus(:iplist_table)
            next
          end

          if !validate_nodeid(UI.QueryWidget(:mynodeid, :Value), up_level_current)
            UI.SetFocus(:mynodeid)
            next
          end

          ret = {}

          if !validate_name(UI.QueryWidget(:mynodename, :Value), iplist, up_level_current)
            UI.SetFocus(:mynodename)
            next
          end
          ret["name"] = UI.QueryWidget(:mynodename, :Value)

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

    def interface_input_dialog(value, transport="knet", link_mode="passive")
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
        links = [value["linknumber"]]
      else
        links = []
      end
      if !Cluster.node_list.empty?
        tmp = Cluster.node_list[0]["IPs"].size
        tmp.times do |index|
          if !links.include?(index) && Cluster.interface_list.size <= index
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
            Left(Label(_("Kronosnet:"))),
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
                Item(Id("udp"), "udp"),
                Item(Id("sctp"), "sctp"),
                ]
              ),
              HSpacing(1),
              MinWidth(20, InputField(Id(:knet_link_priority), _("Knet Link Priority"),
                                      value["knet_link_priority"])),
            ),
            VSpacing(1),
            Left(Label(_("Multicast:"))),
            HBox(
              ComboBox(
                Id(:bindnetaddr),
                Opt(:editable, :hstretch),
                _("Bind Network Address:"),
                bindaddr
              ),
              HSpacing(1),
              MinWidth(20, InputField(Id(:mcastaddr), _("Multicast Address"), value["mcastaddr"])),
              HSpacing(1),
              MinWidth(20, InputField(Id(:mcastport), _("Multicast Port") , value["mcastport"])),
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

      switch_interface_button(transport, link_mode)

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
      if _has_ipfamily_addr("ipv6")
        if UI.QueryWidget(Id(:ip_version), :Value) == "ipv4"
          Popup.Message(_("Found IPv6 address, but configured with IP version ipv4"))
          UI.SetFocus(:ip_version)
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
      end # end _has_ipfamily_addr()

      if _has_ipfamily_addr("ipv4")
        if UI.QueryWidget(Id(:ip_version), :Value) == "ipv6"
          Popup.Message(_("Found IPv4 address, but configured with IP version ipv6"))
          UI.SetFocus(:ip_version)
          return false
        end
      end

      true
    end

    def validate_all_nodes(transport="knet")
      current = 0
      Cluster.node_list.each do |node|
        if !validate_ip_list(node["IPs"], transport)
          return false
        end
        if !validate_nodeid(node["nodeid"], current)
          return false
        end
        if !validate_name(node["name"], node["IPs"], current)
          return false
        end
        node["IPs"].each do |ip|
          if !validate_ip(ip, node["nodeid"])
            return false
          end
        end
        current += 1
      end
      true
    end

    def has_duplicates?(list)
      set = Set.new(list)
      set.size < list.size
    end

    def validate_ip_list(list, transport="knet")
      if has_duplicates?(list)
        Popup.Message(_("Duplicated IP address"))
        return false
      elsif list.size > 8
        Popup.Message(_("Support at most 8 rings"))
        return false
      elsif list.size > 1 && transport != "knet"
        Popup.Message(_("Muiticast and Unicast no longer support multiple rings.\nPlease use Kronosnet"))
        return false
      end
      true
    end

    def validate_ip(ip, self_id="")
      if !ip_matching_check(ip, Cluster.ip_version)
        Popup.Message(_("Invalid IP address: ") + ip)
        return false
      else
        Cluster.node_list.each do |node|
          if node["IPs"].include?(ip)
            if self_id.empty? || node["nodeid"] != self_id
              Popup.Message(_("Duplicated IP address on this node: Node ID: ") + node["nodeid"])
              return false
            end
          end
        end
      end
      true
    end

    def validate_nodeid(nodeid, current=nil)
      if nodeid.empty?
        Popup.Message(_("A Node ID is required"))
        return false
      elsif !valid_nodeid?(nodeid)
        Popup.Message(_("Node ID is required with a positive integer"))
        return false
      else
        nodeid_list = []
        Cluster.node_list.each do |node|
          nodeid_list.push(node["nodeid"])
        end
        if current == nil
          nodeid_list.push(nodeid)
        else
          nodeid_list[current] = nodeid
        end
        if has_duplicates?(nodeid_list)
          Popup.Message(_("Duplicated Node ID"))
          return false
        end
      end
      true
    end

    def validate_name(name, ip_list, current=nil)
      if name.empty? && ip_list.size > 1
        Popup.Message(_("A Node Name is required for multiple links"))
        return false
      else
        name_list = []
        Cluster.node_list.each do |node|
          name_list.push(node["name"])
        end
        if current == nil
          name_list.push(name)
        else
          name_list[current] = name
        end
        if has_duplicates?(name_list)
          Popup.Message(_("Duplicated Node Name"))
          return false
        end
      end
      true
    end

    # BNC#871970, change member address struct
    def ValidateCommunication
      i = 0
      transport = UI.QueryWidget(Id(:transport), :Value).to_s
      if !validate_all_nodes(transport)
        return false
      end
      # Must have cluster name
      if UI.QueryWidget(Id(:cluster_name), :Value) == ""
        Popup.Message(_("The cluster name has to be fulfilled"))
        UI.SetFocus(:cluster_name)
        return false
      end

      # FIXME: if multicast still support not configure node list?
      if Cluster.node_list.size <= 0
        Popup.Message(_("The Node List has to be fulfilled"))
        UI.SetFocus(:nodelist)
        return false
      end

      ringnum = Cluster.node_list[0]["IPs"].size
      if ringnum == 1 && UI.QueryWidget(Id(:linkmode), :Value) != "passive"
        Popup.Message(_("Only one interface is specified, passive linkmode is automatically be chosen"))
        UI.ChangeWidget(Id(:linkmode), :Value, "passive")
        UI.SetFocus(:linkmode)
      end

      if transport == "knet"

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

      # Make sure the ring numbers are the same
      Cluster.node_list.each do |node|
        if node["IPs"].size != ringnum
          Popup.Message(_("The total number of rings must be identical between nodes"))
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
                            (ringnum).to_s)
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
        items = Builtins.add(items, node["nodeid"])
        items = Builtins.add(items, node["name"])

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
            Item(Id("udpu"), "Unicast"),
            Item(Id("udp"), "Multicast")
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
              Header(_("Node ID"), _("Name"), _("Link 0"), _("Link 1"),
                     _("Link 2"), _("More Links...")), table_items),
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
                     _("Bind Net Addr"), _("Mulitcast Addr"), _("Multicast Port")), table_items),
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
            _("Link Mode:"),
            ["passive", "active", "rr"]
          )
        ),
      )

      contents = VBox(
        HBox(hid),
        nodelist_table,
        iface_table,
        HBox(nid),
      )

      my_SetContents("communication", contents)

      UI.ChangeWidget(Id(:cluster_name), :Value, Cluster.cluster_name)

      UI.ChangeWidget(Id(:transport), :Value, Cluster.transport)
      UI.ChangeWidget(Id(:ip_version), :Value, Cluster.ip_version)

      if Cluster.firstrun
        UI.ChangeWidget(Id(:linkmode), :Value, "passive")
        UI.ChangeWidget(Id(:linkmode), :Enabled, false)
      else
        UI.ChangeWidget(Id(:linkmode), :Value, Cluster.link_mode)
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

    def switch_linkmode_button
      if Cluster.node_list.size > 0
        ringnum = Cluster.node_list[0]["IPs"].size
        if ringnum > 1 && Cluster.transport == "knet"
          UI.ChangeWidget(Id(:linkmode), :Enabled, true)
        else
          UI.ChangeWidget(Id(:linkmode), :Enabled, false)
        end
      else
        UI.ChangeWidget(Id(:linkmode), :Enabled, false)
      end
    end

    def CommunicationDialog
      ret = nil

      CommunicationLayout()
      if Cluster.firstrun
        UI.SetFocus(:nodelist_add)
      end
      while true
        fill_nodelist_entries()
        fill_interface_entries()
        switch_linkmode_button()
        switch_nodelist_button(Cluster.node_list)
        switch_interface_list_button(Cluster.interface_list)

        transport = UI.QueryWidget(Id(:transport), :Value).to_s
        link_mode = UI.QueryWidget(Id(:linkmode), :Value).to_s
        ip_version = UI.QueryWidget(Id(:ip_version), :Value).to_s
        if Cluster.firstrun
          if transport == "udp"
            UI.ChangeWidget(Id(:ip_version), :Value, "ipv4")
          else
            UI.ChangeWidget(Id(:ip_version), :Value, "ipv6-4")
          end
        end

        if Cluster.node_list.size > 0 && Cluster.node_list[0]["IPs"].size > Cluster.interface_list.size
          UI.ChangeWidget(Id(:ifacelist_add), :Enabled, true)
        else
          UI.ChangeWidget(Id(:ifacelist_add), :Enabled, false)
        end

        ret = UI.UserInput

        if ret == :nodelist_add
          ret = nodelist_input_dialog({}, transport, ip_version)

          next if ret == :cancel
          Cluster.node_list.push(ret)
        end

        if ret == :nodelist_edit
          current = 0
          current = UI.QueryWidget(:nodelist, :CurrentItem).to_i
          ret = nodelist_input_dialog(Cluster.node_list[current] || {}, transport, ip_version, current)

          next if ret == :cancel
          Cluster.node_list[current] = ret
        end

        if ret == :nodelist_del
          current = 0
          current = UI.QueryWidget(:nodelist, :CurrentItem).to_i
          Cluster.node_list.delete_at(current)
        end

        if ret == :ifacelist_add
          ret = interface_input_dialog({}, transport, link_mode)

          next if ret == :cancel || ret.empty?
          Cluster.interface_list.push(ret)
        end

        if ret == :ifacelist_edit
          current = 0
          current = UI.QueryWidget(:ifacelist, :CurrentItem).to_i
          ret = interface_input_dialog(Cluster.interface_list[current] || {}, transport, link_mode)

          next if ret == :cancel
          # Clear the interface_input_dialog support key in case not configured
          ["linknumber", "knet_transport", "knet_link_priority",
           "bindnetaddr", "mcastaddr", "mcastport"].each do |ele|
            Cluster.interface_list[current].delete(ele)
          end

          # Use merge! since not all parameters show in UI
          Cluster.interface_list[current].merge!(ret)

          if ret.empty? && !Cluster.interface_list[current].empty?
            Popup.Message(_("Found interface parameter configured manually but not support in UI"))
          end
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

    def ValidateSecurity(authkey_created=false)
      if Cluster.transport == "knet"
        if UI.QueryWidget(Id(:secauth), :Value)
          if !authkey_created
            Popup.Message(_("Need to press \"Generate Auth Key File\""))
            UI.SetFocus(:genf)
            return false
          end

          if UI.QueryWidget(Id(:crypto_hash), :Value) == "none"
            Popup.Message(_("Should use valid value of Crypto Hash to encrypt"))
            UI.SetFocus(:crypto_hash)
            return false
          end

          if UI.QueryWidget(Id(:crypto_cipher), :Value) == "none"
            Popup.Message(_("Should use valid value of Crypto Cipher to encrypt"))
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
      Cluster.secauth = Convert.to_boolean(UI.QueryWidget(Id(:secauth), :Value))
      Cluster.crypto_model = UI.QueryWidget(Id(:crypto_model), :Value).to_s
      Cluster.crypto_hash = UI.QueryWidget(Id(:crypto_hash), :Value).to_s
      Cluster.crypto_cipher = UI.QueryWidget(Id(:crypto_cipher), :Value).to_s
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
            MinWidth(20, InputField(Id(:exec_name), _("Execute Name"), name)),
            HSpacing(1),
            MinWidth(55, InputField(Id(:exec_script), _("Execute Script"), script))
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
      if !UI.QueryWidget(Id(:configure_qdevice), :Value)
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

      if !valid_port_number?(UI.QueryWidget(Id(:qdevice_port), :Value))
        Popup.Message(_("Invalid port number for qnetd server"))
        UI.SetFocus(Id(:qdevice_port))
        return false
      end

      if !["lowest", "highest"].include?(UI.QueryWidget(Id(:qdevice_tie_breaker), :Value)) &&
          !valid_nodeid?(UI.QueryWidget(Id(:qdevice_tie_breaker), :Value))
        Popup.Message(_("The tie breaker can be one of lowest, highest or a valid node id (number)"))
        UI.SetFocus(Id(:qdevice_tie_breaker))
        return false
      end

      if UI.QueryWidget(Id(:configure_qdevice), :Value) && Cluster.node_list.size <= 0
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
          Popup.Message(_("The Heuristics Executables script must config if enable Heuristics Mode"))
          return false
        end
      end

      true
    end

    def SaveCorosyncQdevice
      Cluster.configure_qdevice = Convert.to_boolean(UI.QueryWidget(Id(:configure_qdevice), :Value))

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
      ask_config = CheckBox(
        Id(:configure_qdevice), 
        Opt(:notify), 
        "Qnetd Server Host:", 
        Cluster.configure_qdevice
      )

      qdevice_config_base =
        HBox(
          VBox(
            Left(ask_config),
            Left(InputField(Id(:qdevice_host),Opt(:hstretch), _(""),"")),
          ),
          HSpacing(1),
          Left(InputField(Id(:qdevice_port),Opt(:hstretch), _("Qnetd Server TCP port:"),"5403")),
        )

      qdevice_config_advance =
        HBox(
          Left(ComboBox(Id(:qdevice_model),Opt(:hstretch),_("Qdevice Model:"),["net"])),
          HSpacing(1),
          Left(ComboBox(Id(:qdevice_tls), Opt(:hstretch), _("TLS:"),["on", "required", "off"])),
          HSpacing(1),
          Left(ComboBox(Id(:qdevice_algorithm),Opt(:hstretch, :notify), _("Algorithm:"),["ffsplit", "lms"])),
          HSpacing(1),
          Left(InputField(Id(:qdevice_tie_breaker),Opt(:hstretch), _("Tie Breaker:"),"lowest"))
        )

      heuristics_conifg =
        VBox(
          HBox(
            Left(ComboBox(
              Id(:heuristics_mode), Opt(:hstretch, :notify), _("Heuristics Mode:"),
              ["off", "on", "sync"]
            )),
            HSpacing(1),
            Left(InputField(Id(:heuristics_timeout),Opt(:hstretch), _("Heuristics Timeout(ms):"),"5000")),
          ),
          HBox(
            Left(InputField(Id(:heuristics_sync_timeout),Opt(:hstretch), _("Heuristics Sync Timeout(ms):"),"15000")),
            HSpacing(1),
            Left(InputField(Id(:heuristics_interval),Opt(:hstretch), _("Heuristics Interval(ms):"),"30000")),
          )
        )

      heuristics_table =
        VBox(
          Left(Label(_("Heuristics Executables:"))),
          Table(Id(:heuristics_executables), Header(_("Name"), _("Value")), []),
          Right(HBox(
            PushButton(Id(:executable_add), "Add"),
            PushButton(Id(:executable_del), "Del"),
            PushButton(Id(:executable_edit), "Edit"))
          )
        )

      contents =
        Frame(
          _(""),
          VBox(
            qdevice_config_base,
            qdevice_config_advance,
            heuristics_conifg,
            heuristics_table
          )
        )

      my_SetContents("corosyncqdevice", contents)

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

    def qdevice_switch
      enable_widgets(UI.QueryWidget(Id(:configure_qdevice), :Value),
                     :qdevice_host,
                     :qdevice_port, 
                     :qdevice_model, 
                     :qdevice_tls, 
                     :qdevice_tie_breaker, 
                     :qdevice_algorithm, 
                     :heuristics_mode)
      nil
    end

    def heuristics_switch
      if !UI.QueryWidget(Id(:heuristics_mode), :Value) ||
          UI.QueryWidget(Id(:heuristics_mode), :Value) == "off" ||
          !UI.QueryWidget(Id(:configure_qdevice), :Value)
        disable = false
      else
        disable = true
      end
      enable_widgets(disable, 
                     :heuristics_timeout, 
                     :heuristics_sync_timeout, 
                     :heuristics_interval, 
                     :heuristics_executables, 
                     :executable_add, 
                     :executable_edit, 
                     :executable_del)

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
        qdevice_switch

        ret = UI.UserInput

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
                ["aes256", "aes192", "aes128", "none"]
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

      if Cluster.firstrun
        secauth_value = (Cluster.transport == "knet") ? true : false
      else
        secauth_value = Cluster.secauth
      end
      UI.ChangeWidget(Id(:secauth), :Value, secauth_value)
      UI.ChangeWidget(Id(:crypto_model), :Value, Cluster.crypto_model)
      UI.ChangeWidget(Id(:crypto_hash), :Value, Cluster.crypto_hash)
      UI.ChangeWidget(Id(:crypto_cipher), :Value, Cluster.crypto_cipher)
      authkey_path = "/etc/corosync/authkey"

      if UI.QueryWidget(Id(:secauth), :Value) == true
        if (UI.QueryWidget(Id(:crypto_cipher), :Value) != "none" or UI.QueryWidget(Id(:crypto_hash), :Value) != "none") && !File.exist?(authkey_path)
	  UI.SetFocus(:genf)
	end
      end

      if File.exist?(authkey_path)
        authkey_created = true
      else
        authkey_created = false
      end
      while true
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
            Popup.Message(_(format("Failed to create %s", authkey_path)))
          else
            Popup.Message(_(format("Create %s succeeded", authkey_path)))
	    authkey_created = true
            UI.SetFocus(:next)
          end
          next
        end

        if ret ==:secauth
          if UI.QueryWidget(Id(:secauth), :Value) == true
            if Cluster.transport != "knet"
              Popup.Message(_("Encrypted transmission is only supported for the knet transport"))
              UI.ChangeWidget(Id(:secauth), :Value, false)
              next
            end
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

          next
        end

        if ret == :crypto_model || ret == :crypto_cipher || ret == :crypto_hash
          if UI.QueryWidget(Id(:secauth), :Value) == true
            next
          end
        end

        if ret == :next || ret == :back
          val = ValidateSecurity(authkey_created)
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
          val = ValidateSecurity(authkey_created)
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
      if Cluster.configure_qdevice && ret_pacemaker == 0
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
      if Cluster.configure_qdevice
        ret_qdevice_booting = Service.Enabled("corosync-qdevice")
      end
      if Service.Enabled("pacemaker") && ret_qdevice_booting
        UI.ChangeWidget(Id(:status_booting), :Value, _("enabled"))
        UI.ChangeWidget(Id("on"), :Enabled, false)
        UI.ChangeWidget(Id("off"), :Enabled, true)
      else
        UI.ChangeWidget(Id(:status_booting), :Value, _("disabled"))
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
                  # Space is a workaround for possible missing characters
                  Label(Id(:status_booting), _("Enabling     ")),
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
          _("Pacemaker and Corosync start/stop"),
          Left(
            VBox(
              Left(
                HBox(
                  HSpacing(1),
                  Label(_("Current Status: ")),
                  # Space is a workaround for possible missing characters
                  Label(Id(:status), _("Running     ")),
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
          _("Corosync Qdevice start/stop"),
          Left(
            VBox(
              Left(
                HBox(
                  HSpacing(1),
                  Label(_("Current Status: ")),
                  # Space is a workaround for possible missing characters
                  Label(Id(:status_qdevice), _("Running        ")),
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
          if Cluster.configure_qdevice
            Service.Enable("corosync-qdevice")
          end
          next
        end

        if ret == "off"
          Service.Disable("pacemaker")
          if Cluster.configure_qdevice
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
                PushButton(Id(:include_suggest), _("Add Suggested Files")),
                PushButton(Id(:include_add), _("Add")),
                PushButton(Id(:include_del), _("Del")),
                PushButton(Id(:include_edit), _("Edit"))
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
