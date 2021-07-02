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
      @expected_votes = ""
      @two_node = "0"
      @config_format = ""

      @autoid = true

      @corokey = ""
      @csync2key = ""
      @global_startopenais = false
      @global_startcsync2 = false

      @transport = ""

      # example:
      # [{:addr1=>"10.16.35.101",:addr2=>"192.168.0.1", :nodeid=>"1"}, 
      # {:addr1=>"10.16.35.102",:addr2=>"192.168.0.2", :nodeid=>"2"},
      # {:addr1=>"10.16.35.103",:addr2=>"192.168.0.3" },
      # {:addr1=>"10.16.35.104",:nodeid=>"4" },
      # {:addr1=>"10.16.35.105",:nodeid=>"5" }]
      @memberaddr = []
      @address = []

      @corosync_qdevice = false

      @qdevice_model = "net"
      @qdevice_votes = ""

      @qdevice_host = ""
      @qdevice_port = "5403"
      @qdevice_tls = "off"
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
      executables_str = SCR.Read(path(".openais.quorum.device.heuristics.executables"))

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
      if SCR.Read(path(".openais.quorum.device"))
        @corosync_qdevice = true
      end

      if @corosync_qdevice
        @qdevice_model = SCR.Read(path(".openais.quorum.device.model"))
        @qdevice_votes = SCR.Read(path(".openais.quorum.device.votes")).to_s

        @qdevice_host = SCR.Read(path(".openais.quorum.device.net.host"))
        @qdevice_port = SCR.Read(path(".openais.quorum.device.net.port")).to_s
        @qdevice_tls = SCR.Read(path(".openais.quorum.device.net.tls"))
        @qdevice_algorithm = SCR.Read(path(".openais.quorum.device.net.algorithm"))
        @qdevice_tie_breaker = SCR.Read(path(".openais.quorum.device.net.tie_breaker"))

        @heuristics_mode = SCR.Read(path(".openais.quorum.device.heuristics.mode"))
        if @heuristics_mode
          @heuristics_timeout = SCR.Read(path(".openais.quorum.device.heuristics.timeout")).to_s
          @heuristics_sync_timeout = SCR.Read(path(".openais.quorum.device.heuristics.sync_timeout")).to_s
          @heuristics_interval = SCR.Read(path(".openais.quorum.device.heuristics.interval")).to_s
          @heuristics_executables = LoadQdeviceHeuristicsExecutables()
        end
      end

      nil
    end

    def LoadClusterConfig

      if Convert.to_string(SCR.Read(path(".openais.totem.secauth"))) == "on"
        @secauth = true
        @crypto_hash = SCR.Read(path(".openais.totem.crypto_hash"))
        @crypto_cipher = SCR.Read(path(".openais.totem.crypto_cipher"))
      else
        @secauth = false
      end

      @cluster_name = SCR.Read(path(".openais.totem.cluster_name"))

      @ip_version = SCR.Read(path(".openais.totem.ip_version"))

      @expected_votes = SCR.Read(path(".openais.quorum.expected_votes")).to_s

      @config_format = SCR.Read(path(".openais.totem.interface.member.memberaddr")).to_s

      @transport = SCR.Read(path(".openais.totem.transport"))
      @transport = "udp" if @transport == nil
      @address = SCR.Read(path(".openais.nodelist.node")).split(" ")

      interfaces = SCR.Dir(path(".openais.totem.interface"))
      Builtins.foreach(interfaces) do |interface|
        if interface == "interface0"
          if @address != []
            # BNC#871970, change member addresses to nodelist structure
            # memberaddr of udpu only read in interface0
            # address is like "123.3.21.32;156.32.123.1:1 123.3.21.54;156.32.123.4:2 
            # 123.3.21.44;156.32.123.9"
            address = SCR.Read(path(".openais.nodelist.node")).split(" ")
            address.each do |addr|
              p = addr.split("|")
              if p[1] != nil
                q = p[0].split(";")
                if q[1] != nil
                  @memberaddr.push({:addr1=>q[0],:addr2=>q[1],:nodeid=>p[1]})
                else
                  @memberaddr.push({:addr1=>q[0],:nodeid=>p[1]})
                end
              else
                q = p[0].split(";")
                if q[1] != nil
                  @memberaddr.push({:addr1=>q[0],:addr2=>q[1]})
                else
                  @memberaddr.push({:addr1=>q[0]})
                end
              end
            end  # end address.each 
          end

          if @transport == "udp"
            @mcastaddr1 = Convert.to_string(
              SCR.Read(path(".openais.totem.interface.interface0.mcastaddr"))
            )
          end
          @bindnetaddr1 = Convert.to_string(
            SCR.Read(path(".openais.totem.interface.interface0.bindnetaddr"))
          )
          @mcastport1 = Convert.to_string(
            SCR.Read(path(".openais.totem.interface.interface0.mcastport"))
          )
        end
        if interface == "interface1"
          # member address only get in interface0
          if @transport == "udp"
            @mcastaddr2 = Convert.to_string(
              SCR.Read(path(".openais.totem.interface.interface1.mcastaddr"))
            )
          end
          @bindnetaddr2 = Convert.to_string(
            SCR.Read(path(".openais.totem.interface.interface1.bindnetaddr"))
          )
          @mcastport2 = Convert.to_string(
            SCR.Read(path(".openais.totem.interface.interface1.mcastport"))
          )

          @enable2 = true
        end
      end

      ai = Convert.to_string(SCR.Read(path(".openais.totem.autoid")))

      if ai == "yes"
        @autoid = true
      else
        @autoid = false
      end

      @rrpmode = Convert.to_string(SCR.Read(path(".openais.totem.rrpmode")))
      if @enable2 == false
        @rrpmode = "none"
      else
        @rrpmode = "passive" if @rrpmode != "passive" && @rrpmode != "active"
      end

      LoadCorosyncQdeviceConfig()

      nil
    end


    # BNC#871970, generate string like "123.3.21.32;156.32.123.1|1"
    def generateMemberString(memberaddr)
      address_string = ""
      memberaddr.each do |i|
        address_string << i[:addr1]
        if i[:addr2]
          address_string << ";#{i[:addr2]}"
          address_string << "|#{i[:nodeid]}" if i [:nodeid]
        else 
          address_string << "|#{i[:nodeid]}" if i[:nodeid]
        end
        address_string << " "
      end

      return address_string
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
      SCR.Write(path(".openais.quorum.device.model"), @qdevice_model)
      SCR.Write(path(".openais.quorum.device.votes"), @qdevice_votes)

      SCR.Write(path(".openais.quorum.device.net.host"), @qdevice_host)
      SCR.Write(path(".openais.quorum.device.net.port"), @qdevice_port)
      SCR.Write(path(".openais.quorum.device.net.tls"), @qdevice_tls)
      SCR.Write(path(".openais.quorum.device.net.algorithm"), @qdevice_algorithm)
      SCR.Write(path(".openais.quorum.device.net.tie_breaker"), @qdevice_tie_breaker)

      if @heuristics_mode != "off"
        SCR.Write(path(".openais.quorum.device.heuristics.mode"), @heuristics_mode)
        # For @heuristics_xxx doesn't have suggested_value, skip record when empty?
        SCR.Write(path(".openais.quorum.device.heuristics.timeout"), @heuristics_timeout)
        SCR.Write(path(".openais.quorum.device.heuristics.sync_timeout"), @heuristics_sync_timeout)
        SCR.Write(path(".openais.quorum.device.heuristics.interval"), @heuristics_interval)
        executables_str = generateDictString(@heuristics_executables)
        SCR.Write(path(".openais.quorum.device.heuristics.executables"), executables_str)
      else
        SCR.Write(path(".openais.quorum.device.heuristics"), "")
      end

      nil
    end

    def SaveClusterConfig

      if @secauth == true
        SCR.Write(path(".openais.totem.secauth"), "on")
        SCR.Write(path(".openais.totem.crypto_hash"), @crypto_hash)
        SCR.Write(path(".openais.totem.crypto_cipher"), @crypto_cipher)
      else
        SCR.Write(path(".openais.totem.secauth"), "off")
        SCR.Write(path(".openais.totem.crypto_hash"), "none")
        SCR.Write(path(".openais.totem.crypto_cipher"), "none")
      end

      SCR.Write(path(".openais.totem.transport"), @transport)
      SCR.Write(path(".openais.totem.cluster_name"), @cluster_name)
      SCR.Write(path(".openais.totem.ip_version"), @ip_version)
      SCR.Write(path(".openais.quorum.expected_votes"), @expected_votes)

      # BNC#871970, only write member address when interface0  
      if @memberaddr != []

        SCR.Write(
          path(".openais.nodelist.node"),
          generateMemberString(@memberaddr)
        )
      else
        SCR.Write(path(".openais.nodelist.node"), "")
      end
      if @transport == "udp"
        SCR.Write(
          path(".openais.totem.interface.interface0.mcastaddr"),
          @mcastaddr1
        )
        SCR.Write(
          path(".openais.totem.interface.interface0.bindnetaddr"),
          @bindnetaddr1
        )
      else
        SCR.Write(path(".openais.totem.interface.interface0.mcastaddr"), "")
        SCR.Write(path(".openais.totem.interface.interface0.bindnetaddr"), "")
      end

      # BNC#883235. Enable "two_node" when using two node cluster
      if ((@expected_votes == "2") or (@memberaddr.size == 2)) and (!@corosync_qdevice)
        # Set "1" to enable two_node mode when two nodes, otherwise is "0".
        @two_node = "1"
      end

      if @corosync_qdevice
        # two_node can not be used with qdevice
        @two_node = "0"
      end
      SCR.Write(path(".openais.quorum.two_node"), @two_node)

      SCR.Write(
        path(".openais.totem.interface.interface0.mcastport"),
        @mcastport1
      )

      if @enable2 == false
        SCR.Write(path(".openais.totem.interface.interface1"), "")
      else
        if @transport == "udpu"
          SCR.Write(path(".openais.totem.interface.interface1.mcastaddr"), "")
          SCR.Write(path(".openais.totem.interface.interface1.bindnetaddr"), "")
        else
          SCR.Write(
            path(".openais.totem.interface.interface1.mcastaddr"),
            @mcastaddr2
          )
          SCR.Write(
            path(".openais.totem.interface.interface1.bindnetaddr"),
            @bindnetaddr2
          )
        end
        SCR.Write(
          path(".openais.totem.interface.interface1.mcastport"),
          @mcastport2
        )
      end

      #FIXME TODO
      if @autoid == true
        SCR.Write(path(".openais.totem.autoid"), "yes")
      else
        SCR.Write(path(".openais.totem.autoid"), "no")
      end
      SCR.Write(path(".openais.totem.rrpmode"), @rrpmode)

      if @corosync_qdevice
        SaveCorosyncQdeviceConfig()
      else
        SCR.Write(path(".openais.quorum.device"), "")
      end

      SCR.Write(path(".openais"), "")

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

      SCR.Write(path(".sysconfig.pacemaker.LRMD_MAX_CHILDREN"), 4)
      SCR.Write(
        path(".sysconfig.openais.COROSYNC_DEFAULT_CONFIG_IFACE"),
        "openaisserviceenableexperimental:corosync_parser"
      )

      nil
    end

    # Read all cluster settings
    # @return true on success
    def Read
      # Cluster read dialog caption
      caption = _("Initializing cluster Configuration")

      # TODO FIXME Set the right number of stages
      steps = 4

      sl = 500
      Builtins.sleep(sl)

      # TODO FIXME Names of real stages
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
        "corosync-qdevice"
      ]
      ret = PackageSystem.CheckAndInstallPackagesInteractive(required_pack_list)
      if ret == false
        Report.Error(_("Cannot install required package"))
        return false
      end
      # read database
      return false if Abort()
      SCR.Dir(path(".openais"))
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

      # TODO FIXME And set the right number of stages
      steps = 2

      sl = 500

      # TODO FIXME Names of real stages
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
      tcp_ports << @qdevice_port if @corosync_qdevice

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
      if @global_startopenais == true
        SCR.Execute(path(".target.bash_output"), "systemctl enable corosync.service")
      end
      if @global_startcsync2 == true
        SCR.Execute(path(".target.bash_output"), "systemctl enable csync2")
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
      @crypto_hash = settings["crypto_hash"] || "none"
      @crypto_cipher = settings["crypto_cipher"] || "none"
      @transport = Ops.get_string(settings, "transport", "udp")
      @bindnetaddr1 = Ops.get_string(settings, "bindnetaddr1", "")
      @memberaddr = Ops.get_list(settings, "memberaddr", [])
      @mcastaddr1 = Ops.get_string(settings, "mcastaddr1", "")
      @cluster_name  = settings["cluster_name"] || ""
      @ip_version  = settings["ip_version"] || "ipv4"
      @expected_votes = settings["expected_votes"] || ""
      @two_node = settings["two_node"] || ""
      @mcastport2 = Ops.get_string(settings, "mcastport1", "")
      @enable2 = Ops.get_boolean(settings, "enable2", false)
      @bindnetaddr2 = Ops.get_string(settings, "bindnetaddr2", "")
      @mcastaddr2 = Ops.get_string(settings, "mcastaddr2", "")
      @mcastport2 = Ops.get_string(settings, "mcastport2", "")
      @autoid = Ops.get_boolean(settings, "autoid", true)
      @rrpmode = Ops.get_string(settings, "rrpmode", "")

      @corosync_qdevice = settings["corosync_qdevice"] || false
      @qdevice_model = settings["qdevice_model"] || "net"
      @qdevice_votes = settings["qdevice_votes"] || ""
      @qdevice_host = settings["qdevice_host"] || ""
      @qdevice_port = settings["qdevice_port"] || "5403"
      @qdevice_tls = settings["qdevice_tls"] || "off"
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

      @global_startopenais = true
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
      Ops.set(result, "crypto_hash", @crypto_hash)
      Ops.set(result, "crypto_cipher", @crypto_cipher)
      Ops.set(result, "transport", @transport)
      Ops.set(result, "bindnetaddr1", @bindnetaddr1)
      Ops.set(result, "memberaddr", @memberaddr)
      Ops.set(result, "mcastaddr1", @mcastaddr1)
      result["cluster_name"] = @cluster_name
      result["ip_version"] = @ip_version
      result["expected_votes"] = @expected_votes
      result["two_node"] = @two_node
      Ops.set(result, "mcastport1", @mcastport1)
      Ops.set(result, "enable2", @enable2)
      Ops.set(result, "bindnetaddr2", @bindnetaddr2)
      Ops.set(result, "mcastaddr2", @mcastaddr2)
      Ops.set(result, "mcastport2", @mcastport2)
      Ops.set(result, "autoid", true)
      Ops.set(result, "rrpmode", @rrpmode)

      result["corosync_qdevice"] = @corosync_qdevice
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
      if @bindnetaddr1 != ""
        configured = "Corosync is configured<br/>\n"
        configured = Ops.add(
          Ops.add(
            Ops.add(configured, "Ring 1 is configued to use "),
            @bindnetaddr1
          ),
          "<br/>\n"
        )
      end
      if @bindnetaddr2 != ""
        configured = Ops.add(
          Ops.add(
            Ops.add(configured, "Ring 2 is configured to use "),
            @bindnetaddr2
          ),
          "<br/>\n"
        )
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
      { "install" => ["csync2", "pacemaker"], "remove" => [] }
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
    publish :variable => :crypto_hash, :type => "string"
    publish :variable => :crypto_cipher, :type => "string"
    publish :variable => :bindnetaddr1, :type => "string"
    publish :variable => :mcastaddr1, :type => "string"
    publish :variable => :cluster_name, :type => "string"
    publish :variable => :ip_version, :type => "string"
    publish :variable => :expected_votes, :type => "string"
    publish :variable => :corosync_qdevice, :type => "boolean"
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
    publish :variable => :config_format, :type => "string"
    publish :variable => :mcastport1, :type => "string"
    publish :variable => :enable2, :type => "boolean"
    publish :variable => :bindnetaddr2, :type => "string"
    publish :variable => :mcastaddr2, :type => "string"
    publish :variable => :mcastport2, :type => "string"
    publish :variable => :autoid, :type => "boolean"
    publish :variable => :nodeid, :type => "string"
    publish :variable => :rrpmode, :type => "string"
    publish :variable => :corokey, :type => "string"
    publish :variable => :csync2key, :type => "string"
    publish :variable => :global_startopenais, :type => "boolean"
    publish :variable => :global_startcsync2, :type => "boolean"
    publish :variable => :transport, :type => "string"
    publish :variable => :memberaddr, :type => "list <string>"
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
