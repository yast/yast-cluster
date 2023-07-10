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

# File:	modules/Cluster.ycp
# Package:	Configuration of cluster
# Summary:	Cluster settings, input and output functions
# Authors:	Cong Meng <cmeng@novell.com>
#
# $Id: Cluster.ycp 41350 2007-10-10 16:59:00Z dfiser $
#
# Representation of the configuration of cluster.
# Input and output routines.
#
require "yast"
require "y2firewall/firewalld"
require "base64"

module Yast
  class ClusterClass < Module
    def main
      textdomain "cluster"

      Yast.import "Progress"
      Yast.import "Report"
      Yast.import "Summary"
      Yast.import "Message"
      Yast.import "PackageSystem"

      @csync2_key_file = "/etc/csync2/key_hagroup"

      # Data was modified?
      @modified = false

      @proposal_valid = false

      @firstrun = false

      # Write only, used during autoinstallation.
      # Don't run services and SuSEconfig, it's all done at one place.
      @write_only = false

      # Abort function
      # return boolean return true if abort
      @AbortFunction = fun_ref(method(:Modified), "boolean ()")

      # Settings: Define all variables needed for configuration of cluster
      @secauth = false
      @crypto_model = "nss"
      @crypto_hash = "none"
      @crypto_cipher = "none"
      @cluster_name = ""
      @link_mode = "passive"
      @ip_version = "ipv6-4"
      @transport = "knet"

      # example:
      # [{"ttl"=>"190", "mcastport"=>"9999", "mcastaddr"=>"23.45.67.89", "linknumber"=>"9", "knet_link_priority"=>"1"},
      # {"ttl"=>"180", "mcastport"=>"8888", "mcastaddr"=>"1.2.3.4", "linknumber"=>"8"}]
      @interface_list = []

      # example:
      # [{"name"=>"node1", "nodeid"=>"1", "IPs"=>["1.2.3.4", "33:44:11::ff"]},
      # {"name"=>"node2", "nodeid"=>"3", "IPs"=>["ff::11", "ff::11"]},
      # {"name"=>"node3", "nodeid"=>"12", "IPs"=>["22::ee", "11::ff", "aa::44"]},
      # {"name"=>"dummy", "IPs"=>["ff::ff"]}]
      @node_list = []

      @expected_votes = ""
      @two_node = "0"

      @corokey = ""
      @csync2key = ""
      @global_startcorosync = false
      @global_startcsync2 = false

      @configure_qdevice = false

      @qdevice_model = "net"
      @qdevice_votes = ""

      @qdevice_host = ""
      @qdevice_port = "5403"
      @qdevice_tls = "on"
      @qdevice_algorithm = "ffsplit"
      @qdevice_tie_breaker = "lowest"

      # qdevice heuristics
      @heuristics_mode = "off"
      @heuristics_timeout = "5000"
      @heuristics_sync_timeout = "15000"
      @heuristics_interval = "30000"
      @heuristics_executables = {}

      @csync2_host = []
      @csync2_include = []
    end

    # Abort function
    # @return [Boolean] return true if abort
    def Abort
      return @AbortFunction.call == true if @AbortFunction != nil
      false
    end

    # Data was modified?
    # @return true if modified
    def Modified
      Builtins.y2debug("modified=%1", @modified)
      @modified
    end

    # Mark as modified, for Autoyast.
    def SetModified(value)
      @modified = true

      nil
    end

    def ProposalValid
      @proposal_valid
    end

    def SetProposalValid(value)
      @proposal_valid = value

      nil
    end

    # @return true if module is marked as "write only" (don't start services etc...)
    def WriteOnly
      @write_only
    end

    # Set write_only flag (for autoinstalation).
    def SetWriteOnly(value)
      @write_only = value

      nil
    end


    def SetAbortFunction(function)
      function = deep_copy(function)
      @AbortFunction = deep_copy(function)

      nil
    end

    def LoadQdeviceHeuristicsExecutables
      executables = {}
      executables_str = SCR.Read(path(".corosync.quorum.device.heuristics.executables"))

      if executables_str
        executables_ori = eval(executables_str)
        # with eval(), key will have extra ""
        # {'exec_check': '/tmp/check.sh'}
        # {:exec_check=>"/tmp/check.sh"}
        executables_ori.each do |key, value|
          executables[key.to_s] = value.to_s
        end
      end

      executables
    end

    def LoadCorosyncQdeviceConfig
      if SCR.Read(path(".corosync.quorum.device"))
        @configure_qdevice = true
      end

      if @configure_qdevice
        @qdevice_model = SCR.Read(path(".corosync.quorum.device.model"))
        @qdevice_votes = SCR.Read(path(".corosync.quorum.device.votes")).to_s

        @qdevice_host = SCR.Read(path(".corosync.quorum.device.net.host"))
        @qdevice_port = SCR.Read(path(".corosync.quorum.device.net.port")).to_s
        @qdevice_tls = SCR.Read(path(".corosync.quorum.device.net.tls"))
        @qdevice_algorithm = SCR.Read(path(".corosync.quorum.device.net.algorithm"))
        @qdevice_tie_breaker = SCR.Read(path(".corosync.quorum.device.net.tie_breaker"))

        @heuristics_mode = SCR.Read(path(".corosync.quorum.device.heuristics.mode"))
        if @heuristics_mode
          @heuristics_timeout = SCR.Read(path(".corosync.quorum.device.heuristics.timeout")).to_s
          @heuristics_sync_timeout = SCR.Read(path(".corosync.quorum.device.heuristics.sync_timeout")).to_s
          @heuristics_interval = SCR.Read(path(".corosync.quorum.device.heuristics.interval")).to_s
          @heuristics_executables = LoadQdeviceHeuristicsExecutables()
        end
      end

      nil
    end

    def LoadClusterConfig

      if Convert.to_string(SCR.Read(path(".corosync.totem.secauth"))) == "on"
        @secauth = true
        @crypto_model = SCR.Read(path(".corosync.totem.crypto_model"))
        @crypto_hash = SCR.Read(path(".corosync.totem.crypto_hash"))
        @crypto_cipher = SCR.Read(path(".corosync.totem.crypto_cipher"))
      else
        @secauth = false
      end

      @link_mode = SCR.Read(path(".corosync.totem.link_mode"))
      @cluster_name = SCR.Read(path(".corosync.totem.cluster_name"))
      @ip_version = SCR.Read(path(".corosync.totem.ip_version"))

      @expected_votes = SCR.Read(path(".corosync.quorum.expected_votes")).to_s

      @transport = SCR.Read(path(".corosync.totem.transport"))
      @transport = "knet" if @transport == nil

      interfaces = SCR.Dir(path(".corosync.totem.interface"))
      interfaces.each do |index|
        ikeys = SCR.Dir(path(".corosync.totem.interface." + index))
        interface = {}
        ikeys.each do |key|
          interface[key] = SCR.Read(path(".corosync.totem.interface." + index + "." + key))
        end
        @interface_list.push(interface)
      end

      nodes = SCR.Dir(path(".corosync.nodelist.node"))
      nodes.each do |index|
        nkeys = SCR.Dir(path(".corosync.nodelist.node." + index))
        node = {}
        nkeys.each do |key|
          # Ignore ring0_addr..ringX_addr. Use IPs as a list only
          if key.match?("ring")
            next
          end

          # corosync3: addresses is like "123.3.21.32;156.32.123.1;123.3.21.54;156.32.123.4"
          if key == "IPs"
            address_list = SCR.Read(path(".corosync.nodelist.node." + index + "." + key)).split(";")
            node[key] = address_list
            next
          end

          node[key] = SCR.Read(path(".corosync.nodelist.node." + index + "." + key))
        end
        @node_list.push(node)
      end

      LoadCorosyncQdeviceConfig()

      nil
    end

    def generateDictString(obj)
      str = "{"
      first = true

      obj.each do |k, v|
        if not first
          str << ", "
        end

        str << "'" + k.to_s + "'"
        str << ": "
        str << "'" + v.to_s + "'"
        first = false
      end

      str << "}"
    end

    def SaveCorosyncQdeviceConfig
      SCR.Write(path(".corosync.quorum.device.model"), @qdevice_model)
      SCR.Write(path(".corosync.quorum.device.votes"), @qdevice_votes)

      SCR.Write(path(".corosync.quorum.device.net.host"), @qdevice_host)
      SCR.Write(path(".corosync.quorum.device.net.port"), @qdevice_port)
      SCR.Write(path(".corosync.quorum.device.net.tls"), @qdevice_tls)
      SCR.Write(path(".corosync.quorum.device.net.algorithm"), @qdevice_algorithm)
      SCR.Write(path(".corosync.quorum.device.net.tie_breaker"), @qdevice_tie_breaker)

      if @heuristics_mode != "off"
        SCR.Write(path(".corosync.quorum.device.heuristics.mode"), @heuristics_mode)
        # For @heuristics_xxx doesn't have suggested_value, skip record when empty?
        SCR.Write(path(".corosync.quorum.device.heuristics.timeout"), @heuristics_timeout)
        SCR.Write(path(".corosync.quorum.device.heuristics.sync_timeout"), @heuristics_sync_timeout)
        SCR.Write(path(".corosync.quorum.device.heuristics.interval"), @heuristics_interval)
        executables_str = generateDictString(@heuristics_executables)
        SCR.Write(path(".corosync.quorum.device.heuristics.executables"), executables_str)
      else
        SCR.Write(path(".corosync.quorum.device.heuristics"), "")
      end

      nil
    end

    def SaveClusterConfig

      if @secauth == true and @transport == "knet"
        SCR.Write(path(".corosync.totem.secauth"), "on")
        SCR.Write(path(".corosync.totem.crypto_model"), @crypto_model)
        SCR.Write(path(".corosync.totem.crypto_hash"), @crypto_hash)
        SCR.Write(path(".corosync.totem.crypto_cipher"), @crypto_cipher)
      else
        SCR.Write(path(".corosync.totem.secauth"), "off")
        SCR.Write(path(".corosync.totem.crypto_model"), "")
        SCR.Write(path(".corosync.totem.crypto_hash"), "")
        SCR.Write(path(".corosync.totem.crypto_cipher"), "")
      end

      SCR.Write(path(".corosync.totem.transport"), @transport)
      SCR.Write(path(".corosync.totem.cluster_name"), @cluster_name)
      SCR.Write(path(".corosync.totem.ip_version"), @ip_version)
      SCR.Write(path(".corosync.totem.link_mode"), @link_mode)
      # FIXME: if support no nodelist in corosync3
      # Only write expected_votes when no node list
      if @node_list.empty?
        SCR.Write(path(".corosync.quorum.expected_votes"), @expected_votes)
      else
        SCR.Write(path(".corosync.quorum.expected_votes"), "")
      end

      # Initialize totem.interface list
      SCR.Write(path(".corosync.totem.interface"), "")
      if @interface_list != []
        for i in 0..(interface_list.length() - 1)
          for k in interface_list[i].keys()
            # Do not write knet_parameters when udp/udpe
            if @transport != "knet"
              ignore_list = ["knet_link_priority", "knet_ping_interval",
                             "knet_ping_timeout", "knet_ping_precision",
                             "knet_pong_count", "knet_transport"]

              if ignore_list.include?(k)
                next
              end
            end

            SCR.Write(
              path(".corosync.totem.interface." + i.to_s + "." + k),
              interface_list[i][k]
            )
          end
        end
      end

      # Initialize nodelist.node list
      SCR.Write(path(".corosync.nodelist.node"), "")
      if @node_list!= []
        for i in 0..(node_list.length() - 1)
          for k in node_list[i].keys()
            if k == "IPs"
              SCR.Write(
                path(".corosync.nodelist.node." + i.to_s + ".IPs"),
				node_list[i]["IPs"].join(";")
              )
              next
            end

            SCR.Write(
              path(".corosync.nodelist.node." + i.to_s + "." + k),
              node_list[i][k]
            )
          end
        end
      end

      # BNC#883235. Enable "two_node" when using two node cluster
      if ((@expected_votes == "2") or (@node_list.size == 2)) and (!@configure_qdevice)
        # Set "1" to enable two_node mode when two nodes, otherwise is "0".
        @two_node = "1"
      end

      if @configure_qdevice
        # two_node can not be used with qdevice
        @two_node = "0"
      end
      SCR.Write(path(".corosync.quorum.two_node"), @two_node)

      if @configure_qdevice
        SaveCorosyncQdeviceConfig()
      else
        SCR.Write(path(".corosync.quorum.device"), "")
      end

      SCR.Write(path(".corosync"), "")

      nil
    end

    def load_csync2_conf
      @csync2_host = Convert.convert(
        SCR.Read(path(".csync2_ha.value.ha_group.host")),
        :from => "any",
        :to   => "list <string>"
      )
      @csync2_include = Convert.convert(
        SCR.Read(path(".csync2_ha.value.ha_group.include")),
        :from => "any",
        :to   => "list <string>"
      )

      @csync2_host = [] if @csync2_host == nil
      @csync2_include = [] if @csync2_include == nil
      Builtins.y2milestone("read csync2 conf: csync2_host = %1", @csync2_host)
      Builtins.y2milestone(
        "read csync2 conf: csync2_include = %1",
        @csync2_include
      )

      nil
    end

    def save_csync2_conf
      Builtins.y2milestone("write csync2 conf: csync2_host = %1", @csync2_host)
      Builtins.y2milestone(
        "write csync2 conf: csync2_include = %1",
        @csync2_include
      )

      SCR.Write(path(".csync2_ha.value.ha_group.host"), @csync2_host)
      SCR.Write(path(".csync2_ha.value.ha_group.include"), @csync2_include)
      SCR.Write(path(".csync2_ha.value.ha_group.key"), [@csync2_key_file])
      SCR.Write(path(".csync2_ha"), nil)

      SCR.Write(path(".sysconfig.pacemaker.LRMD_MAX_CHILDREN"), 4)
      SCR.Write(path(".sysconfig.pacemaker"), nil)
      nil
    end

    # Read all cluster settings
    # @return true on success
    def Read
      # Cluster read dialog caption
      caption = _("Initializing cluster Configuration")

      # Set the right number of stages
      steps = 3

      sl = 500
      Builtins.sleep(sl)

      # We do not set help text here, because it was set outside
      Progress.New(
        caption,
        " ",
        steps,
        [
          # Progress stage 1/3
          _("Read the database"),
          # Progress stage 2/3
          _("Read the previous settings"),
          # Progress stage 3/3
          _("Read Firewall Settings")
        ],
        [
          # Progress step 1/3
          _("Reading the database..."),
          # Progress step 2/3
          _("Reading the previous settings..."),
          # Progress step 3/3
          _("Reading Firewall settings..."),
          # Progress finished
          _("Finished")
        ],
        ""
      )

      ret = false
      required_pack_list = [
        "pacemaker",
        "csync2",
        "conntrack-tools",
        "hawk2",
        "crmsh",
        "corosync",
        "corosync-qdevice",
        "libknet1",
        "libknet1-plugins-all",
      ]
      ret = PackageSystem.CheckAndInstallPackagesInteractive(required_pack_list)
      if ret == false
        Report.Error(_("Cannot install required package"))
        return false
      end
      # read database
      return false if Abort()
      SCR.Dir(path(".corosync"))
      ret = false
      ret = LoadClusterConfig()
      if ret == false
        Report.Error(_("Cannot load existing configuration"))
        return false
      end
      if Ops.less_or_equal(
          SCR.Read(path(".target.size"), "/etc/corosync/corosync.conf"),
          1
        )
        @firstrun = true
      end
      Progress.NextStage
      # Error message
      Report.Error(_("Cannot read database1.")) if false
      Builtins.sleep(sl)

      load_csync2_conf
      # read another database
      return false if Abort()
      Progress.NextStep
      # Error message
      Report.Error(_("Cannot read database2.")) if false
      Builtins.sleep(sl)

      # read current settings
      return false if Abort()
      Progress.NextStage
      # Error message
      Report.Error(Message.CannotReadCurrentSettings) if false
      Builtins.sleep(sl)

      # detect devices
      firewalld.read

      return false if Abort()
      Progress.NextStage
      # Error message
      Report.Warning(_("Cannot detect devices.")) if false
      Builtins.sleep(sl)

      return false if Abort()
      # Progress finished
      Progress.NextStage
      Builtins.sleep(sl)

      return false if Abort()
      Progress.Finish
      @modified = false
      true
    end

    # Write all cluster settings
    # @return true on success
    def Write
      # Cluster read dialog caption
      caption = _("Saving cluster Configuration")

      # Set the right number of stages
      steps = 2

      sl = 500

      # Names of real stages
      # We do not set help text here, because it was set outside
      Progress.New(
        caption,
        " ",
        steps,
        [
          # Progress stage 1/2
          _("Write the settings"),
          # Progress stage 2/2
          _("Save firewall changes")
        ],
        [
          # Progress step 1/2
          _("Writing the settings..."),
          # Progress step 2/2
          _("Saving firewall changes ..."),
          # Progress finished
          _("Finished")
        ],
        ""
      )

      # write settings
      SaveClusterConfig()
      return false if Abort()
      Progress.NextStage
      # Error message
      Report.Error(_("Cannot write settings.")) if false
      Builtins.sleep(sl)

      # Work with firewalld
      udp_ports = []
      for interface in interface_list
        if interface.has_key?("mcastport") and not udp_ports.include?(interface["mcastport"])
          udp_ports << interface["mcastport"]
        end
      end

      # 30865 for csync2
      # 5560 for mgmtd
      # 7630 for hawk or hawk2
      # 21064 for dlm
      # 5403 for corosync qdevice(default)
      tcp_ports = ["30865", "5560", "21064", "7630"]
      tcp_ports << @qdevice_port if @configure_qdevice

      begin
        Y2Firewall::Firewalld::Service.modify_ports(name: "cluster", tcp_ports: tcp_ports, udp_ports: udp_ports)
      rescue Y2Firewall::Firewalld::Service::NotFound
        y2error("Firewalld 'cluster' service is not available.")
      end

      save_csync2_conf

      # run SuSEconfig
      firewalld.write
      return false if Abort()
      Progress.NextStage
      # Error message
      Report.Error(Message.SuSEConfigFailed) if false
      Builtins.sleep(sl)

      return false if Abort()
      # Progress finished
      Progress.NextStage
      Builtins.sleep(sl)

      if @corokey != ""
        if system("which 'uudecode'>/dev/null 2>&1")
          cmd = "echo '" + @corokey + "' | uudecode -o /etc/corosync/authkey"
          %x[ #{cmd} ]
        else
          File.write("/etc/corosync/authkey", Base64.decode64(@corokey))
        end
      end
      if @csync2key != ""
        if system("which 'uudecode'>/dev/null 2>&1")
          cmd = "echo '" + @csync2key + "' | uudecode -o " + @csync2_key_file
          %x[ #{cmd} ]
        else
          File.write(@csync2_key_file, Base64.decode64(@csync2key))
        end
      end
      # is that necessary? since enable pacemaker will trigger corosync/csync2?
      # FIXME if not necessary
      if @global_startcorosync == true
        SCR.Execute(path(".target.bash_output"), "systemctl enable corosync.service")
      end
      if @global_startcsync2 == true
        SCR.Execute(path(".target.bash_output"), "systemctl enable csync2.socket")
      end

      return false if Abort()
      Progress.Finish
      true
    end

    # Get all cluster settings from the first parameter
    # (For use by autoinstallation.)
    # @param [Hash] settings The YCP structure to be imported.
    # @return [Boolean] True on success
    # BNC#871970 , change to memberaddr. But seems still not functional
    def Import(settings)
      settings = deep_copy(settings)
      @secauth = Ops.get_boolean(settings, "secauth", false)
      @crypto_model = settings["crypto_model"] || "nss"
      @crypto_hash = settings["crypto_hash"] || "none"
      @crypto_cipher = settings["crypto_cipher"] || "none"
      @link_mode = settings["link_mode"] || "passive"
      @transport = Ops.get_string(settings, "transport", "udp")
      @cluster_name  = settings["cluster_name"] || ""
      @ip_version  = settings["ip_version"] || "ipv4"
      @expected_votes = settings["expected_votes"] || ""
      @two_node = settings["two_node"] || ""
      @interface_list = settings["interface_list"] || []
      @node_list = settings["node_list"] || []

      @configure_qdevice = settings["configure_qdevice"] || false
      @qdevice_model = settings["qdevice_model"] || "net"
      @qdevice_votes = settings["qdevice_votes"] || ""
      @qdevice_host = settings["qdevice_host"] || ""
      @qdevice_port = settings["qdevice_port"] || "5403"
      @qdevice_tls = settings["qdevice_tls"] || "on"
      @qdevice_algorithm= settings["qdevice_algorithm"] || "ffsplit"
      @qdevice_tie_breaker = settings["qdevice_tie_breaker"] || "lowest"

      @heuristics_mode = settings["heuristics_mode"] || "off"
      @heuristics_timeout = settings["heuristics_timeout"] || "5000"
      @heuristics_sync_timeout = settings["heuristics_sync_timeout"] || "15000"
      @heuristics_interval = settings["heuristics_interval"] || "30000"
      @heuristics_executables = settings["heuristics_executables"] || {}

      @corokey = Ops.get_string(settings, "corokey", "")
      @csync2key = Ops.get_string(settings, "csync2key", "")

      @csync2_host = Ops.get_list(settings, "csync2_host", [])
      @csync2_include = Ops.get_list(settings, "csync2_include", [])

      @global_startcorosync = true
      @global_startcsync2 = true
      true
    end

    # Dump the cluster settings to a single map
    # (For use by autoinstallation.)
    # @return [Hash] Dumped settings (later acceptable by Import ())
    # BNC#871970 , change to memberaddr. But seems still not functional
    def Export
      result = {}
      Ops.set(result, "secauth", @secauth)
      result["crypto_model"] = @crypto_model
      Ops.set(result, "crypto_hash", @crypto_hash)
      Ops.set(result, "crypto_cipher", @crypto_cipher)
      Ops.set(result, "transport", @transport)
      result["link_mode"] = @link_mode
      result["cluster_name"] = @cluster_name
      result["ip_version"] = @ip_version
      result["expected_votes"] = @expected_votes
      result["two_node"] = @two_node
      result["interface_list"] = @interface_list
      result["node_list"] = @node_list

      result["configure_qdevice"] = @configure_qdevice
      result["qdevice_model"] = @qdevice_model
      result["qdevice_votes"] = @qdevice_votes
      result["qdevice_host"] = @qdevice_host
      result["qdevice_port"] = @qdevice_port
      result["qdevice_tls"] = @qdevice_tls
      result["qdevice_algorithm"] = @qdevice_algorithm
      result["qdevice_tie_breaker"] = @qdevice_tie_breaker

      result["heuristics_mode"] = @heuristics_mode
      result["heuristics_timeout"] = @heuristics_timeout
      result["heuristics_sync_timeout"] = @heuristics_sync_timeout
      result["heuristics_interval"] = @heuristics_interval
      result["heuristics_executables"] = @heuristics_executables

      Ops.set(result, "csync2_host", @csync2_host)
      Ops.set(result, "csync2_include", @csync2_include)
      if File.exist?("/etc/corosync/authkey")
        if system("which 'uuencode'>/dev/null 2>&1")
          data = %x[ #{'uuencode -m /etc/corosync/authkey /dev/stdout'} ]
          Ops.set(result, "corokey", data)
        else
          data = File.read("/etc/corosync/authkey")
          Ops.set(result, "corokey", Base64.encode64(data))
        end
      end

      if File.exist?(@csync2_key_file)
        if system("which 'uuencode'>/dev/null 2>&1")
          data = %x[ #{'uuencode -m ' + @csync2_key_file + ' /dev/stdout'} ]
          Ops.set(result, "csync2key", data)
        else
          data = File.read(@csync2_key_file)
          Ops.set(result, "csync2key", Base64.encode64(data))
        end
      end
      deep_copy(result)
    end

    # Create a textual summary and a list of unconfigured cards
    # @return summary of the current configuration
    def Summary
      # Configuration summary text for autoyast
      configured = ""
      if @transport != ""
        configured = "Corosync is configured<br/>\n"
        configured += "Corosync is configued to use " + @transport + "<br/>\n"
      end

      configured = "Change the configuration of HAE here..." if configured == ""

      [configured, []]
    end

    # Create an overview table with all configured cards
    # @return table items
    def Overview
      []
    end

    # Return packages needed to be installed and removed during
    # Autoinstallation to insure module has all needed software
    # installed.
    # @return [Hash] with 2 lists.
    def AutoPackages
      { "install" => ["csync2", "pacemaker", "corosync", "corosync-qdevice",
					  "hawk2", "libknet1"], "remove" => [] }
    end

    publish :variable => :csync2_key_file, :type => "string"
    publish :function => :Modified, :type => "boolean ()"
    publish :variable => :firstrun, :type => "boolean"
    publish :function => :Abort, :type => "boolean ()"
    publish :function => :SetModified, :type => "void (boolean)"
    publish :function => :ProposalValid, :type => "boolean ()"
    publish :function => :SetProposalValid, :type => "void (boolean)"
    publish :function => :WriteOnly, :type => "boolean ()"
    publish :function => :LoadClusterConfig, :type => "boolean ()"
    publish :function => :LoadCorosyncQdeviceConfig, :type => "boolean ()"
    publish :function => :SetWriteOnly, :type => "void (boolean)"
    publish :function => :SetAbortFunction, :type => "void (boolean ())"
    publish :variable => :secauth, :type => "boolean"
    publish :variable => :crypto_model, :type => "string"
    publish :variable => :crypto_hash, :type => "string"
    publish :variable => :crypto_cipher, :type => "string"
    publish :variable => :link_mode, :type => "string"
    publish :variable => :cluster_name, :type => "string"
    publish :variable => :ip_version, :type => "string"
    publish :variable => :expected_votes, :type => "string"
    publish :variable => :configure_qdevice, :type => "boolean"
    publish :variable => :qdevice_model, :type => "string"
    publish :variable => :qdevice_votes, :type => "string"
    publish :variable => :qdevice_host, :type => "string"
    publish :variable => :qdevice_port, :type => "string"
    publish :variable => :qdevice_tls, :type => "string"
    publish :variable => :qdevice_algorithm, :type => "string"
    publish :variable => :qdevice_tie_breaker, :type => "string"
    publish :variable => :heuristics_mode, :type => "string"
    publish :variable => :heuristics_timeout, :type => "string"
    publish :variable => :heuristics_sync_timeout, :type => "string"
    publish :variable => :heuristics_interval, :type => "string"
    publish :variable => :heuristics_executables, :type => "map <string, string>"
    publish :variable => :two_node, :type => "string"
    publish :variable => :corokey, :type => "string"
    publish :variable => :csync2key, :type => "string"
    publish :variable => :global_startcorosync, :type => "boolean"
    publish :variable => :global_startcsync2, :type => "boolean"
    publish :variable => :transport, :type => "string"
    publish :variable => :interface_list, :type => "list <string>"
    publish :variable => :node_list, :type => "list <string>"
    publish :function => :SaveClusterConfig, :type => "void ()"
    publish :function => :SaveCorosyncQdeviceConfig, :type => "void ()"
    publish :variable => :csync2_host, :type => "list <string>"
    publish :variable => :csync2_include, :type => "list <string>"
    publish :function => :load_csync2_conf, :type => "void ()"
    publish :function => :save_csync2_conf, :type => "void ()"
    publish :function => :Read, :type => "boolean ()"
    publish :function => :Write, :type => "boolean ()"
    publish :function => :Import, :type => "boolean (map)"
    publish :function => :Export, :type => "map ()"
    publish :function => :Summary, :type => "list ()"
    publish :function => :Overview, :type => "list ()"
    publish :function => :AutoPackages, :type => "map ()"

  private

    def firewalld
      Y2Firewall::Firewalld.instance
    end

  end

  Cluster = ClusterClass.new
  Cluster.main
end
