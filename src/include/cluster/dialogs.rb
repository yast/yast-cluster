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
      Yast.import "SuSEFirewall"
      Yast.import "SuSEFirewallServices"

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
        "/etc/booth/booth.conf",
        "/etc/sysconfig/sbd",
        "/etc/csync2/csync2.cfg",
        "/etc/csync2/key_hagroup"
      ]

      @csync2_port = "30865"

      # This is the list of usable interface for conntrackd
      @usable_interface = []
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

    def addr_input_dialog(value, autoid, dual)
      ret = nil

      value.default=""
 
      # BNC#871970, change member address struct
      UI.OpenDialog(
        MarginBox(
          1,
          1,
          VBox(
            HBox(
            MinWidth(40, InputField(Id(:addr1), _("IP Address"), value[:addr1])),
            HSpacing(1),
            MinWidth(40, InputField(Id(:addr2), _("Redundant IP Address"), value[:addr2])),
            HSpacing(1),
            MinWidth(20, InputField(Id(:mynodeid), _("nodeid") , value[:nodeid]))
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

      if (autoid)
        UI.ChangeWidget(:mynodeid, :Enabled, false)
      end

      if (!dual)
        UI.ChangeWidget(:addr2, :Enabled, false)
      end

      ret = UI.UserInput
      if ret == :ok
        if ( UI.QueryWidget(:mynodeid, :Value) != "" ) && ( UI.QueryWidget(:addr2, :Value) != "" )
          ret = {:addr1 => UI.QueryWidget(:addr1, :Value), :addr2 => UI.QueryWidget(:addr2, :Value), :nodeid => UI.QueryWidget(:mynodeid, :Value)}
        elsif ( UI.QueryWidget(:mynodeid, :Value) == "" ) && ( UI.QueryWidget(:addr2, :Value) != "" )
          ret = {:addr1 => UI.QueryWidget(:addr1, :Value), :addr2 => UI.QueryWidget(:addr2, :Value)}
        elsif ( UI.QueryWidget(:mynodeid, :Value) != "" ) && ( UI.QueryWidget(:addr2, :Value) == "" )
          ret = {:addr1 => UI.QueryWidget(:addr1, :Value), :nodeid => UI.QueryWidget(:mynodeid, :Value)}
        else
          ret = {:addr1 => UI.QueryWidget(:addr1, :Value)}
        end
      end
      UI.CloseDialog
      deep_copy(ret)
    end

    def ValidNodeID
      if Cluster.memberaddr.size <= 0
         return true
      end

      i = 0
      # Set need to require 'set'
      idset = Set[]

      Builtins.foreach(Cluster.memberaddr) do |value|
        if  value[:nodeid].to_i <= 0
          Popup.Message("Node ID has to be fulfilled with a positive integer")
          UI.ChangeWidget(:memberaddr, :CurrentItem, i)
          i = 0
          raise Break
        end

        if idset.include?(value[:nodeid].to_i)
          Popup.Message("Node ID must be unique")
          UI.ChangeWidget(:memberaddr, :CurrentItem, i)
          i = 0
          raise Break
        end

        idset << value[:nodeid].to_i
        i = Ops.add(i, 1)
      end

      if i == 0
        return false
      end

      true
    end
 
    # BNC#871970, change member address struct
    def ValidateCommunication
      i = 0
      if IP.Check(Convert.to_string(UI.QueryWidget(Id(:bindnetaddr1), :Value))) == false
        Popup.Message("The Bind Network Address has to be fulfilled")
        UI.SetFocus(:bindnetaddr1)
        return false
      end

      if UI.QueryWidget(Id(:cluster_name), :Value) == ""
        Popup.Message("The cluster name has to be fulfilled")
        UI.SetFocus(:cluster_name)
        return false
      end

      if UI.QueryWidget(Id(:transport), :Value) == "udpu"
        i = 0
        Builtins.foreach(Cluster.memberaddr) do |value|
          if  !IP.Check(value[:addr1]) || ( UI.QueryWidget(Id(:enable2), :Value) && !IP.Check(value[:addr2]) )
            UI.ChangeWidget(:memberaddr, :CurrentItem, i)
            i = 0
            raise Break
          end
          i = Ops.add(i, 1)
        end
        if i == 0
          UI.SetFocus(:memberaddr)
          Popup.Message("The Member Address has to be fulfilled")
          return false
        end
      else
        #BNC#880242, expected_votes must have value when "udp"
        if UI.QueryWidget(Id(:expected_votes), :Value) == ""
          Popup.Message("The expected votes has to be fulfilled when udp")
          UI.SetFocus(:expected_votes)
          return false
        end

        if !IP.Check(Convert.to_string(UI.QueryWidget(Id(:mcastaddr1), :Value)))
          Popup.Message("The Multicast Address has to be fulfilled")
          UI.SetFocus(:mcastaddr1)
          return false
        end
      end

      if !Builtins.regexpmatch(
          Convert.to_string(UI.QueryWidget(Id(:mcastport1), :Value)),
          "^[0-9]+$"
        )
        Popup.Message("The Multicast port must be a positive integer")
        UI.SetFocus(Id(:mcastport1))
        return false
      end

      if UI.QueryWidget(Id(:enable2), :Value)
        if IP.Check(
            Convert.to_string(UI.QueryWidget(Id(:bindnetaddr2), :Value))
          ) == false
          Popup.Message("The Bind Network Address has to be fulfilled")
          UI.SetFocus(:bindnetaddr2)
          return false
        end

        if UI.QueryWidget(Id(:transport), :Value) == "udp"
          if IP.Check(
              Convert.to_string(UI.QueryWidget(Id(:mcastaddr2), :Value))
            ) == false
            Popup.Message("The Multicast Address has to be fulfilled")
            UI.SetFocus(:mcastaddr2)
            return false
          end
        end

        if !Builtins.regexpmatch(
            Convert.to_string(UI.QueryWidget(Id(:mcastport2), :Value)),
            "^[0-9]+$"
          )
          Popup.Message("The Multicast port must be a positive integer")
          UI.SetFocus(Id(:mcastport2))
          return false
        end

        if UI.QueryWidget(Id(:rrpmode), :Value) == "none"
          Popup.Message("Only passive or active can be chosen if multiple interface used. Set to passive.")
          UI.ChangeWidget(Id(:rrpmode), :Value, "passive")
          UI.SetFocus(Id(:rrpmode))
          return false
        end
      end

      if !UI.QueryWidget(Id(:autoid), :Value ) && ( UI.QueryWidget(Id(:transport), :Value) == "udpu" )
        ret = ValidNodeID()
        if !ret
           UI.SetFocus(Id(:memberaddr))
           return false
        end
      end

      true
    end

    def SaveCommunicationToConf
      SCR.Write(
        path(".openais.totem.interface.interface0.bindnetaddr"),
        Convert.to_string(UI.QueryWidget(Id(:bindnetaddr1), :Value))
      )
      SCR.Write(
        path(".openais.totem.interface.interface0.mcastaddr"),
        Convert.to_string(UI.QueryWidget(Id(:mcastaddr1), :Value))
      )
      SCR.Write(
        path(".openais.totem.interface.interface0.mcastport"),
        Convert.to_string(UI.QueryWidget(Id(:mcastport1), :Value))
      )

      if !UI.QueryWidget(Id(:enable2), :Value)
        SCR.Write(path(".openais.totem.interface.interface1"), "")
      else
        SCR.Write(
          path(".openais.totem.interface.interface1.bindnetaddr"),
          Convert.to_string(UI.QueryWidget(Id(:bindnetaddr2), :Value))
        )
        SCR.Write(
          path(".openais.totem.interface.interface1.mcastaddr"),
          Convert.to_string(UI.QueryWidget(Id(:mcastaddr2), :Value))
        )
        SCR.Write(
          path(".openais.totem.interface.interface1.mcastport"),
          Convert.to_string(UI.QueryWidget(Id(:mcastport2), :Value))
        )
      end

      if UI.QueryWidget(Id(:autoid), :Value)
        SCR.Write(path(".openais.totem.autoid"), "yes")
      else
        SCR.Write(path(".openais.totem.autoid"), "no")
      end

      SCR.Write(
        path(".openais.totem.rrpmode"),
        Convert.to_string(UI.QueryWidget(Id(:rrpmode), :Value))
      )

      nil
    end

    def SaveCommunication
      Cluster.bindnetaddr1 = Convert.to_string(
        UI.QueryWidget(Id(:bindnetaddr1), :Value)
      )
      Cluster.bindnetaddr2 = Convert.to_string(
        UI.QueryWidget(Id(:bindnetaddr2), :Value)
      )
      Cluster.mcastaddr1 = Convert.to_string(
        UI.QueryWidget(Id(:mcastaddr1), :Value)
      )
      Cluster.mcastaddr2 = Convert.to_string(
        UI.QueryWidget(Id(:mcastaddr2), :Value)
      )
      Cluster.mcastport1 = Convert.to_string(
        UI.QueryWidget(Id(:mcastport1), :Value)
      )
      Cluster.mcastport2 = Convert.to_string(
        UI.QueryWidget(Id(:mcastport2), :Value)
      )
      Cluster.enable2 = Convert.to_boolean(UI.QueryWidget(Id(:enable2), :Value))
      Cluster.autoid = Convert.to_boolean(UI.QueryWidget(Id(:autoid), :Value))
      Cluster.rrpmode = Convert.to_string(UI.QueryWidget(Id(:rrpmode), :Value))
      Cluster.cluster_name = UI.QueryWidget(Id(:cluster_name), :Value)
      Cluster.expected_votes = UI.QueryWidget(Id(:expected_votes), :Value).to_s
      Cluster.transport = Convert.to_string(
        UI.QueryWidget(Id(:transport), :Value)
      )

      #BNC#871970, clear second IP when redundant channel is disabled
      if !UI.QueryWidget(Id(:enable2), :Value)
        Cluster.memberaddr.each { |member| member[:addr2] = "" }
      end

      if UI.QueryWidget(Id(:autoid), :Value)
        Cluster.memberaddr.each  { |member| member[:nodeid] = "" }
      end

      nil
    end

    #only work when IPv4
    def calc_network_addr(ip, mask)
      IP.ToString(
        Ops.bitwise_and(
          IP.ToInteger(ip),
          Ops.shift_left(4294967295, Ops.subtract(32, Builtins.tointeger(mask)))
        )
      )
    end


    # BNC#871970, change member address struct to memberaddr
    def transport_switch
      udp = UI.QueryWidget(Id(:transport), :Value) == "udp"
      enable2 = UI.QueryWidget(Id(:enable2), :Value)

      enable1 = udp
      enable2 = udp && enable2

      UI.ChangeWidget(Id(:mcastaddr1), :Enabled, enable1)
      UI.ChangeWidget(Id(:memberaddr), :Enabled, !enable1)
      UI.ChangeWidget(Id(:memberaddr_add), :Enabled, !enable1)
      UI.ChangeWidget(Id(:memberaddr_del), :Enabled, !enable1)
      UI.ChangeWidget(Id(:memberaddr_edit), :Enabled, !enable1)

      UI.ChangeWidget(Id(:mcastaddr2), :Enabled, enable2)

      nil
    end


    # BNC#871970, change member address struct to memberaddr
    def CommunicationLayout
      result = {}

      result = Convert.to_map(
        SCR.Execute(
          path(".target.bash_output"),
          "/sbin/ip addr show scope global | grep inet | awk '{print $2}' | awk -F'/' '{print $1, $2}'"
        )
      )

      existing_ips = []
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
            existing_ips = Builtins.add(
              existing_ips,
              calc_network_addr(ip, mask)
            )
          end
        end
      end

      transport = ComboBox(
        Id(:transport),
        Opt(:hstretch, :notify),
        _("Transport:"),
        ["udp", "udpu"]
      )

      iface = Frame(
        _("Channel"),
        VBox(
          ComboBox(
            Id(:bindnetaddr1),
            Opt(:editable, :hstretch, :notify),
            _("Bind Network Address:"),
            Builtins.toset(existing_ips)
          ),
          InputField(
            Id(:mcastaddr1),
            Opt(:hstretch, :notify),
            _("Multicast Address:")
          ),
          InputField(Id(:mcastport1), Opt(:hstretch), _("Multicast Port:")),
        )
      )

      riface = CheckBoxFrame(
        Id(:enable2),
        Opt(:notify),
        _("Redundant Channel"),
        false,
        VBox(
          ComboBox(
            Id(:bindnetaddr2),
            Opt(:editable, :hstretch, :notify),
            _("Bind Network Address:"),
            existing_ips
          ),
          InputField(Id(:mcastaddr2), Opt(:hstretch), _("Multicast Address:")),
          InputField(Id(:mcastport2), Opt(:hstretch), _("Multicast Port:")),
        )
      )

      nid = VBox(
        HBox(
          Left(InputField(Id(:cluster_name),Opt(:hstretch), _("Cluster Name:"))),
          Left(InputField(Id(:expected_votes),Opt(:hstretch), _("expected votes:"),"")),
          ComboBox(
            Id(:rrpmode),
            Opt(:hstretch),
            _("rrp mode:"),
            ["none", "active", "passive"]
          )
        ),
        Left(
          CheckBox(Id(:autoid), Opt(:notify), _("Auto Generate Node ID"), true)
        )
      )

      ip_table = VBox(
        Left(Label(_("Member Address:"))),
        Table(Id(:memberaddr), Header("IP", "Redundant IP", "nodeid"), []),
        Right(HBox(
          PushButton(Id(:memberaddr_add), "Add"),
          PushButton(Id(:memberaddr_del), "Del"),
          PushButton(Id(:memberaddr_edit), "Edit"))
        ))

      contents = VBox(
        transport,
        HBox(HWeight(1, VBox(iface)), HWeight(1, VBox(riface))),
        ip_table,
        HBox(nid),
      )

      my_SetContents("communication", contents)

      UI.ChangeWidget(Id(:bindnetaddr1), :Value, Cluster.bindnetaddr1)
      UI.ChangeWidget(Id(:mcastaddr1), :Value, Cluster.mcastaddr1)
      UI.ChangeWidget(Id(:mcastport1), :Value, Cluster.mcastport1)
      UI.ChangeWidget(Id(:enable2), :Value, Cluster.enable2)
      UI.ChangeWidget(Id(:bindnetaddr2), :Value, Cluster.bindnetaddr2)
      UI.ChangeWidget(Id(:mcastaddr2), :Value, Cluster.mcastaddr2)
      UI.ChangeWidget(Id(:mcastport2), :Value, Cluster.mcastport2)

      UI.ChangeWidget(Id(:autoid), :Value, Cluster.autoid)
      UI.ChangeWidget(Id(:cluster_name), :Value, Cluster.cluster_name)
      UI.ChangeWidget(Id(:expected_votes), :Value, Cluster.expected_votes)
      UI.ChangeWidget(:expected_votes, :ValidChars, "0123456789" );

      UI.ChangeWidget(Id(:transport), :Value, Cluster.transport)

      UI.ChangeWidget(Id(:rrpmode), :Value, Cluster.rrpmode)
      if "none" == Cluster.rrpmode
        UI.ChangeWidget(Id(:rrpmode), :Enabled, false)
      else
        UI.ChangeWidget(Id(:rrpmode), :Enabled, true)
      end

      # BNC#879596, check the corosync.conf format
      if Cluster.config_format == "old"
        Popup.Message(" NOTICE: Detected old corosync configuration.\n Please reconfigure the member list and confirm all other settings.")
        Cluster.config_format = "showed"
      end

      transport_switch

      nil
    end


    def fill_memberaddr_entries
      i = 0
      ret = 0
      current = 0
      items = []

      # BNC#871970,change structure
      # remove duplicated elements
      Cluster.memberaddr = Ops.add(Cluster.memberaddr, [])

      i = 0
      items = []
      Builtins.foreach(Cluster.memberaddr) do |value|
          items.push(Item(Id(i), value[:addr1],value[:addr2], value[:nodeid]))
          i += 1
      end

      current = Convert.to_integer(UI.QueryWidget(:memberaddr, :CurrentItem))
      current = 0 if current == nil
      current = Ops.subtract(i, 1) if Ops.greater_or_equal(current, i)
      UI.ChangeWidget(:memberaddr, :Items, items)
      UI.ChangeWidget(:memberaddr, :CurrentItem, current)

      nil
    end

    def CommunicationDialog
      ret = nil

      CommunicationLayout()


      while true
        fill_memberaddr_entries
        transport_switch

        ret = UI.UserInput

        if ret == :bindnetaddr1 || ret == :bindnetaddr2 || ret == :mcastaddr1 ||
            ret == :mcastaddr2
          ip6 = false
          netaddr = Convert.to_string(UI.QueryWidget(Id(ret), :Value))
          ip6 = IP.Check6(netaddr)
          if ip6
            UI.ChangeWidget(Id(:autoid), :Value, false)
            UI.ChangeWidget(Id(:autoid), :Enabled, false)
          else
            UI.ChangeWidget(Id(:autoid), :Enabled, true)
          end
          next
        end

        if ret == :enable2
          if UI.QueryWidget(Id(:enable2), :Value)
            # Changewidget items will change value to first one automatically
            rrpvalue = UI.QueryWidget(Id(:rrpmode), :Value)
            UI.ChangeWidget(Id(:rrpmode), :Items, ["passive","active"])
            UI.ChangeWidget(Id(:rrpmode), :Enabled, true)
            UI.ChangeWidget(Id(:rrpmode), :Value, rrpvalue) if rrpvalue != "none"
          else
            UI.ChangeWidget(Id(:rrpmode), :Items, ["none"])
            UI.ChangeWidget(Id(:rrpmode), :Value, "none")
            UI.ChangeWidget(Id(:rrpmode), :Enabled, false)
          end
        end

        if ret == :memberaddr_add
          ret = addr_input_dialog({}, UI.QueryWidget(Id(:autoid), :Value), UI.QueryWidget(Id(:enable2), :Value))
          next if ret == :cancel
          Cluster.memberaddr.push(ret)
        end

        if ret == :memberaddr_edit
          current = 0
          str = ""

          # The value will be nil if the list is empty, however nil.to_i is 0
          current = UI.QueryWidget(:memberaddr, :CurrentItem).to_i

          ret = addr_input_dialog(Cluster.memberaddr[current] || {} ,UI.QueryWidget(Id(:autoid), :Value ), UI.QueryWidget(Id(:enable2), :Value))
          next if ret == :cancel
          Cluster.memberaddr[current]= ret
        end

        if ret == :memberaddr_del
          current = 0
          current = Convert.to_integer(
            UI.QueryWidget(:memberaddr, :CurrentItem)
          )
          # Notice, current could be "nil" if the list is empty.
          Cluster.memberaddr = Builtins.remove(Cluster.memberaddr, current)
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
      ret = true
      if UI.QueryWidget(Id(:secauth), :Value) == true
        thr = Convert.to_string(UI.QueryWidget(Id(:threads), :Value))
        s = Builtins.regexpmatch(thr, "^[0-9]+$")
        if !s
          Popup.Message("Number of threads must be integer")
          UI.SetFocus(Id(:threads))
          ret = false
        end
        i = Builtins.tointeger(thr)
        if i == 0
          Popup.Message("Number of threads must larger then 0")
          UI.SetFocus(Id(:threads))
          ret = false
        end
      end
      ret
    end

    def SaveSecurityToConf
      if UI.QueryWidget(Id(:secauth), :Value) == true
        SCR.Write(path(".openais.totem.secauth"), "on")
        SCR.Write(
          path(".openais.totem.threads"),
          Convert.to_string(UI.QueryWidget(Id(:threads), :Value))
        )
      else
        SCR.Write(path(".openais.totem.secauth"), "off")
        SCR.Write(path(".openais.totem.threads"), "")
      end

      nil
    end

    def SaveSecurity
      Cluster.secauth = Convert.to_boolean(UI.QueryWidget(Id(:secauth), :Value))
      Cluster.threads = Convert.to_string(UI.QueryWidget(Id(:threads), :Value))

      nil
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
            InputField(Id(:threads), Opt(:hstretch), _("Threads:")),
            VSpacing(1),
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

      UI.ChangeWidget(Id(:threads), :Value, Cluster.threads)

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
            Popup.Message("Failed to create /etc/corosync/authkey")
          else
            Popup.Message("Create /etc/corosync/authkey succeeded")
          end
          next
        end

        if ret == :secauth
          if UI.QueryWidget(Id(:secauth), :Value) == true
            thr = Convert.to_string(UI.QueryWidget(Id(:threads), :Value))
            if thr == "" || thr == "0"
              result = {}
              t = 0
              result = Convert.to_map(
                SCR.Execute(
                  path(".target.bash_output"),
                  "grep processor /proc/cpuinfo | wc -l"
                )
              )
              t = Builtins.tointeger(Ops.get_string(result, "stdout", ""))
              t = 0 if t == nil
              UI.ChangeWidget(Id(:threads), :Value, Builtins.sformat("%1", t))
            end
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
      ret = 0
      ret = Service.Status("pacemaker")
      if ret == 0
        UI.ChangeWidget(Id(:status), :Value, _("Running"))
      else
        UI.ChangeWidget(Id(:status), :Value, _("Not running"))
      end
      UI.ChangeWidget(Id("start_now"), :Enabled, ret != 0)
      UI.ChangeWidget(Id("stop_now"), :Enabled, ret == 0)

      if not Service.Enabled("pacemaker")
        UI.ChangeWidget(Id("off"), :Value, true)
        UI.ChangeWidget(Id("on"), :Value, false)
      else
        UI.ChangeWidget(Id("on"), :Value, true)
        UI.ChangeWidget(Id("off"), :Value, false)
      end

      nil
    end

    def ServiceDialog
      ret = nil


      firewall_widget = CWMFirewallInterfaces.CreateOpenFirewallWidget(
        {
          #servie:cluster is the  name of /etc/sysconfig/SuSEfirewall2.d/services/cluster
          "services"        => [
            "service:cluster"
          ],
          "display_details" => true
        }
      )
      Builtins.y2milestone("%1", firewall_widget)
      firewall_layout = Ops.get_term(firewall_widget, "custom_widget", VBox())


      contents = VBox(
        VSpacing(1),
        Frame(
          _("Booting"),
          RadioButtonGroup(
            Id("bootcorosync"),
            HBox(
              HSpacing(1),
              VBox(
                Left(
                  RadioButton(
                    Id("on"),
                    Opt(:notify),
                    _("On -- Start pacemaker at booting")
                  )
                ),
                Left(
                  RadioButton(
                    Id("off"),
                    Opt(:notify),
                    _("Off -- Start pacemaker manually only")
                  )
                )
              )
            )
          )
        ),
        VSpacing(1),
        Frame(
          _("Switch On and Off"),
          Left(
            VBox(
              Left(
                HBox(
                  Label(_("Current Status: ")),
                  Label(Id(:status), _("Running")),
                  ReplacePoint(Id("status_rp"), Empty())
                )
              ),
              Left(
                HBox(
                  HSpacing(1),
                  HBox(
                    PushButton(Id("start_now"), _("Start pacemaker Now")),
                    PushButton(Id("stop_now"), _("Stop pacemaker Now"))
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
          next
        end

        if ret == "off"
          Service.Disable("pacemaker")
          next
        end

        # pacemaker will start corosync automatically.
        # BNC#872651 is fixed, so stop pacemaker could stop corosync at the same time.
        if ret == "start_now"
          Cluster.save_csync2_conf
          Cluster.SaveClusterConfig
          # BNC#872651 , add more info about error message
          Report.Error(Service.Error + errormsg) if !Service.Start("pacemaker")
          next
        end

        if ret == "stop_now"
          # BNC#874563,stop pacemaker could stop corosync since BNC#872651 is fixed
          Report.Error(Service.Error + errormsg) if !Service.Stop("pacemaker")
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
      ret = nil

      ret = Convert.to_map(
        SCR.Execute(path(".target.bash_output"), "/sbin/chkconfig csync2")
      )
      Builtins.y2milestone("chkconfig csync2 = %1", ret)
      if Builtins.issubstring(
          Ops.get_string(ret, "stderr", ""),
          "command not found"
        ) == true
        return 1
      end
      if Builtins.issubstring(
          Ops.get_string(ret, "stderr", ""),
          "unknown service"
        ) == true
        return 1
      end
      if Builtins.issubstring(Ops.get_string(ret, "stdout", ""), "off") == true
        return 2
      end
      #check the firewall whether csync2 port was blocked.
      tcp_ports = []
      tcp_ports = SuSEFirewallServices.GetNeededTCPPorts("service:cluster")
      pos = nil
      pos = Builtins.find(tcp_ports) { |s| s == @csync2_port }
      return 2 if pos == nil

      3
    end

    def try_restart_xinetd
      r = Service.RunInitScript("xinetd", "restart")
      Builtins.y2debug("try_restart_xinetd return %1", r)
      r
    end

    def csync2_turn_off
      SCR.Execute(path(".target.bash_output"), "/sbin/chkconfig csync2 off")
      tcp_ports = []
      tcp_ports = SuSEFirewallServices.GetNeededTCPPorts("service:cluster")
      pos = nil
      pos = Builtins.find(tcp_ports) { |s| s == @csync2_port }
      if pos != nil
        tcp_ports = Builtins.remove(tcp_ports, Builtins.tointeger(pos))
      end
      SuSEFirewallServices.SetNeededPortsAndProtocols(
        "service:cluster",
        { "tcp_ports" => tcp_ports }
      )

      try_restart_xinetd

      nil
    end

    def csync2_turn_on
      SCR.Execute(path(".target.bash_output"), "/sbin/chkconfig csync2 on")

      tcp_ports = []
      tcp_ports = SuSEFirewallServices.GetNeededTCPPorts("service:cluster")
      pos = nil
      pos = Builtins.find(tcp_ports) { |s| s == @csync2_port }
      tcp_ports = Builtins.add(tcp_ports, @csync2_port) if pos == nil
      SuSEFirewallServices.SetNeededPortsAndProtocols(
        "service:cluster",
        { "tcp_ports" => tcp_ports }
      )

      SCR.Execute(path(".target.bash_output"), "/sbin/chkconfig xinetd on")
      try_restart_xinetd

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
          str = ""

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
        Popup.Message("The Multicast Address has to be fulfilled")
        UI.SetFocus(:conntrack_addr)
        return false
      end
      if !Builtins.regexpmatch(
          Convert.to_string(UI.QueryWidget(Id(:conntrack_group), :Value)),
          "^[0-9]+$"
        )
        Popup.Message("The Group Number must be a positive integer")
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
  end
end
