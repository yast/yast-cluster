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

module Yast
  class ClusterClass < Module
    def main
      textdomain "cluster"

      Yast.import "Progress"
      Yast.import "Report"
      Yast.import "Summary"
      Yast.import "Message"
      Yast.import "PackageSystem"
      Yast.import "SuSEFirewall"
      Yast.import "SuSEFirewallServices"


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
      @cluster_name = ""
      @ip_version = ""
      @expected_votes = ""
      @two_node = "0"
      @config_format = ""

      @bindnetaddr1 = ""
      @mcastaddr1 = ""
      @mcastport1 = ""
      @enable2 = false
      @bindnetaddr2 = ""
      @mcastaddr2 = ""
      @mcastport2 = ""

      @autoid = true
      @rrpmode = ""

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

    def LoadClusterConfig

      if Convert.to_string(SCR.Read(path(".openais.totem.secauth"))) == "on"
        @secauth = true
      else
        @secauth = false
      end

      @cluster_name = SCR.Read(path(".openais.totem.cluster_name"))

      @ip_version = SCR.Read(path(".openais.totem.ip_version"))

      @expected_votes = SCR.Read(path(".openais.quorum.expected_votes")).to_s

      @config_format = SCR.Read(path(".openais.totem.interface.member.memberaddr")).to_s

      @transport = SCR.Read(path(".openais.totem.transport"))
      @transport = "udp" if @transport == nil

      interfaces = SCR.Dir(path(".openais.totem.interface"))
      Builtins.foreach(interfaces) do |interface|
        if interface == "interface0"
          if @transport == "udpu"
            # BNC#871970, change member addresses to nodelist structure
            # memberaddr of udpu only read in interface0
            # address is like "123.3.21.32;156.32.123.1:1 123.3.21.54;156.32.123.4:2 
            # 123.3.21.44;156.32.123.9"
            address = SCR.Read(path(".openais.nodelist.node")).split(" ")
            address.each do |addr|
              p = addr.split("-")
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

          else
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

      nil
    end


    # BNC#871970, generate string like "123.3.21.32;156.32.123.1:1"
    def generateMemberString(memberaddr)
      address_string = ""
      memberaddr.each do |i|
        address_string << i[:addr1]
        if i[:addr2]
          address_string << ";#{i[:addr2]}"
          address_string << "-#{i[:nodeid]}" if i [:nodeid]
        else 
          address_string << "-#{i[:nodeid]}" if i[:nodeid]
        end
        address_string << " "
      end

      return address_string
    end

    def SaveClusterConfig

      if @secauth == true
        SCR.Write(path(".openais.totem.secauth"), "on")
      else
        SCR.Write(path(".openais.totem.secauth"), "off")
      end

      SCR.Write(path(".openais.totem.transport"), @transport)
      SCR.Write(path(".openais.totem.cluster_name"), @cluster_name)
      SCR.Write(path(".openais.totem.ip_version"), @ip_version)
      SCR.Write(path(".openais.quorum.expected_votes"), @expected_votes)
  
      # BNC#871970, only write member address when interface0  
      if @transport == "udpu"

        SCR.Write(
          path(".openais.nodelist.node"),
          generateMemberString(@memberaddr)
        )
        SCR.Write(path(".openais.totem.interface.interface0.mcastaddr"), "")
      else
        SCR.Write(
          path(".openais.totem.interface.interface0.mcastaddr"),
          @mcastaddr1
        )
        SCR.Write(path(".openais.nodelist.node"), "")
      end

      # BNC#883235. Enable "two_node" when using two node cluster
      if (@expected_votes == "2") or (@transport == "udpu" && @memberaddr.size == 2)
        # Set "1" to enable two_node mode when two nodes, otherwise is "0".
        @two_node = "1"
      end
      SCR.Write(path(".openais.quorum.two_node"), @two_node)

      SCR.Write(
        path(".openais.totem.interface.interface0.bindnetaddr"),
        @bindnetaddr1
      )
      SCR.Write(
        path(".openais.totem.interface.interface0.mcastport"),
        @mcastport1
      )

      if @enable2 == false
        SCR.Write(path(".openais.totem.interface.interface1"), "")
      else
        if @transport == "udpu"
          SCR.Write(path(".openais.totem.interface.interface1.mcastaddr"), "")
        else
          SCR.Write(
            path(".openais.totem.interface.interface1.mcastaddr"),
            @mcastaddr2
          )
        end
        SCR.Write(
          path(".openais.totem.interface.interface1.bindnetaddr"),
          @bindnetaddr2
        )
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
          _("Read SuSEFirewall Settings")
        ],
        [
          # Progress step 1/3
          _("Reading the database..."),
          # Progress step 2/3
          _("Reading the previous settings..."),
          # Progress step 3/3
          _("Reading SuSEFirewall settings..."),
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
        "crmsh"
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
      SuSEFirewall.Read

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
          _("Save changes to SuSEFirewall")
        ],
        [
          # Progress step 1/2
          _("Writing the settings..."),
          # Progress step 2/2
          _("Saving changes to SuSEFirewall..."),
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

      # Work with SuSEFirewall
      udp_ports = []
      udp_ports = Builtins.add(udp_ports, @mcastport1) if @mcastport1 != ""
      if @enable2 && @mcastport2 != ""
        udp_ports = Builtins.add(udp_ports, @mcastport2)
      end

      temp_tcp_ports = ["21064", "7630"]
      tcp_ports = SuSEFirewallServices.GetNeededTCPPorts("service:cluster")
      tcp_ports = Convert.convert(
        Builtins.union(tcp_ports, temp_tcp_ports),
        :from => "list",
        :to   => "list <string>"
      )

      SuSEFirewallServices.SetNeededPortsAndProtocols(
        "service:cluster",
        { "tcp_ports" => tcp_ports, "udp_ports" => udp_ports }
      )

      save_csync2_conf

      # run SuSEconfig
      SuSEFirewall.Write
      return false if Abort()
      Progress.NextStage
      # Error message
      Report.Error(Message.SuSEConfigFailed) if false
      Builtins.sleep(sl)

      SuSEFirewall.ActivateConfiguration
      return false if Abort()
      # Progress finished
      Progress.NextStage
      Builtins.sleep(sl)

      if @corokey != ""
        out = Convert.to_map(
          SCR.Execute(
            path(".target.bash_output"),
            Ops.add(
              Ops.add("echo '", @corokey),
              "' | uudecode -o /etc/corosync/authkey"
            )
          )
        )
      end
      if @csync2key != ""
        out = Convert.to_map(
          SCR.Execute(
            path(".target.bash_output"),
            Ops.add(
              Ops.add(Ops.add("echo '", @csync2key), "' | uudecode -o "),
              @csync2_key_file
            )
          )
        )
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
      Ops.set(result, "csync2_host", @csync2_host)
      Ops.set(result, "csync2_include", @csync2_include)
      if SCR.Read(path(".target.size"), "/etc/corosync/authkey") != -1
        out = Convert.to_map(
          SCR.Execute(
            path(".target.bash_output"),
            "uuencode -m /etc/corosync/authkey /dev/stdout"
          )
        )
        Ops.set(result, "corokey", Ops.get_string(out, "stdout", ""))
      end
      if SCR.Read(path(".target.size"), "/etc/csync2/key_hagroup") != -1
        out = Convert.to_map(
          SCR.Execute(
            path(".target.bash_output"),
            Ops.add(Ops.add("uuencode -m ", @csync2_key_file), " /dev/stdout ")
          )
        )
        Ops.set(result, "csync2key", Ops.get_string(out, "stdout", ""))
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
    publish :function => :SetWriteOnly, :type => "void (boolean)"
    publish :function => :SetAbortFunction, :type => "void (boolean ())"
    publish :variable => :secauth, :type => "boolean"
    publish :variable => :bindnetaddr1, :type => "string"
    publish :variable => :mcastaddr1, :type => "string"
    publish :variable => :cluster_name, :type => "string"
    publish :variable => :ip_version, :type => "string"
    publish :variable => :expected_votes, :type => "string"
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
  end

  Cluster = ClusterClass.new
  Cluster.main
end
