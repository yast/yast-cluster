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
      @use_mgmtd = false
      @secauth = false
      @threads = ""

      @bindnetaddr1 = ""
      @mcastaddr1 = ""
      @mcastport1 = ""
      @enable2 = false
      @bindnetaddr2 = ""
      @mcastaddr2 = ""
      @mcastport2 = ""

      @autoid = true
      @nodeid = ""
      @rrpmode = ""

      @corokey = ""
      @csync2key = ""
      @global_startopenais = false
      @global_startcsync2 = false

      @transport = ""
      @memberaddr1 = []
      @memberaddr2 = []

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
      if Convert.to_string(SCR.Read(path(".openais.pacemaker.use_mgmtd"))) == "yes"
        @use_mgmtd = true
      else
        @use_mgmtd = false
      end

      if Convert.to_string(SCR.Read(path(".openais.totem.secauth"))) == "on"
        @secauth = true
      else
        @secauth = false
      end

      @threads = Convert.to_string(SCR.Read(path(".openais.totem.threads")))

      @transport = Convert.to_string(SCR.Read(path(".openais.totem.transport")))
      @transport = "udp" if @transport == nil

      interfaces = SCR.Dir(path(".openais.totem.interface"))
      Builtins.foreach(interfaces) do |interface|
        if interface == "interface0"
          if @transport == "udpu"
            @memberaddr1 = Builtins.splitstring(
              Convert.to_string(
                SCR.Read(path(".openais.totem.interface.interface0.member"))
              ),
              " "
            )
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
          if @transport == "udpu"
            @memberaddr2 = Builtins.splitstring(
              Convert.to_string(
                SCR.Read(path(".openais.totem.interface.interface1.member"))
              ),
              " "
            )
          else
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

      if ai == "yes" || ai == "new"
        @autoid = true
      else
        @autoid = false
      end

      @nodeid = Convert.to_string(SCR.Read(path(".openais.totem.nodeid")))

      @rrpmode = Convert.to_string(SCR.Read(path(".openais.totem.rrpmode")))
      if @enable2 == false
        @rrpmode = "none"
      else
        @rrpmode = "passive" if @rrpmode != "passive" && @rrpmode != "active"
      end

      nil
    end

    def SaveClusterConfig
      if @use_mgmtd == true
        SCR.Write(path(".openais.pacemaker.use_mgmtd"), "yes")
      else
        SCR.Write(path(".openais.pacemaker.use_mgmtd"), "no")
      end

      if @secauth == true
        SCR.Write(path(".openais.totem.secauth"), "on")
        SCR.Write(path(".openais.totem.threads"), @threads)
      else
        SCR.Write(path(".openais.totem.secauth"), "off")
        SCR.Write(path(".openais.totem.threads"), "")
      end

      SCR.Write(path(".openais.totem.transport"), @transport)

      if @transport == "udpu"
        SCR.Write(
          path(".openais.totem.interface.interface0.member"),
          Builtins.mergestring(@memberaddr1, " ")
        )
        SCR.Write(path(".openais.totem.interface.interface0.mcastaddr"), "")
      else
        SCR.Write(
          path(".openais.totem.interface.interface0.mcastaddr"),
          @mcastaddr1
        )
        SCR.Write(path(".openais.totem.interface.interface0.member"), "")
      end
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
          SCR.Write(
            path(".openais.totem.interface.interface1.member"),
            Builtins.mergestring(@memberaddr2, " ")
          )
          SCR.Write(path(".openais.totem.interface.interface1.mcastaddr"), "")
        else
          SCR.Write(
            path(".openais.totem.interface.interface1.mcastaddr"),
            @mcastaddr2
          )
          SCR.Write(path(".openais.totem.interface.interface1.member"), "")
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

      if @autoid == true
        SCR.Write(path(".openais.totem.autoid"), "new")
        SCR.Write(path(".openais.totem.nodeid"), "")
      else
        SCR.Write(path(".openais.totem.nodeid"), @nodeid)
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
        "pacemaker-mgmt",
        "pacemaker-mgmt-client",
        "csync2",
        "conntrack-tools",
        "hawk",
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
        @use_mgmtd = true #the only interested default option
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
      Builtins.sleep(sl)

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
      if @use_mgmtd == true
        temp_tcp_ports = Builtins.add(temp_tcp_ports, "5560")
      end
      #Union
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
      if @global_startopenais == true
        SCR.Execute(path(".target.bash_output"), "/sbin/chkconfig openais on")
      end
      if @global_startcsync2 == true
        SCR.Execute(path(".target.bash_output"), "/sbin/chkconfig csync2 on")
      end

      return false if Abort()
      true
    end

    # Get all cluster settings from the first parameter
    # (For use by autoinstallation.)
    # @param [Hash] settings The YCP structure to be imported.
    # @return [Boolean] True on success
    def Import(settings)
      settings = deep_copy(settings)
      @use_mgmtd = Ops.get_boolean(settings, "use_mgmtd", true)
      @secauth = Ops.get_boolean(settings, "secauth", false)
      @threads = Ops.get_string(settings, "threads", "")
      @transport = Ops.get_string(settings, "transport", "udp")
      @bindnetaddr1 = Ops.get_string(settings, "bindnetaddr1", "")
      @memberaddr1 = Ops.get_list(settings, "memberaddr1", [])
      @mcastaddr1 = Ops.get_string(settings, "mcastaddr1", "")
      @mcastport1 = Ops.get_string(settings, "mcastport1", "")
      @enable2 = Ops.get_boolean(settings, "enable2", false)
      @bindnetaddr2 = Ops.get_string(settings, "bindnetaddr2", "")
      @memberaddr2 = Ops.get_list(settings, "memberaddr2", [])
      @mcastaddr2 = Ops.get_string(settings, "mcastaddr2", "")
      @mcastport2 = Ops.get_string(settings, "mcastport2", "")
      @autoid = Ops.get_boolean(settings, "autoid", true)
      @nodeid = ""
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
    def Export
      result = {}
      Ops.set(result, "use_mgmtd", @use_mgmtd)
      Ops.set(result, "secauth", @secauth)
      Ops.set(result, "threads", @threads)
      Ops.set(result, "transport", @transport)
      Ops.set(result, "bindnetaddr1", @bindnetaddr1)
      Ops.set(result, "memberaddr1", @memberaddr1)
      Ops.set(result, "mcastaddr1", @mcastaddr1)
      Ops.set(result, "mcastport1", @mcastport1)
      Ops.set(result, "enable2", @enable2)
      Ops.set(result, "bindnetaddr2", @bindnetaddr2)
      Ops.set(result, "memberaddr2", @memberaddr2)
      Ops.set(result, "mcastaddr2", @mcastaddr2)
      Ops.set(result, "mcastport2", @mcastport2)
      Ops.set(result, "autoid", true)
      Ops.set(result, "nodeid", "")
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
      # TODO FIXME: your code here...
      []
    end

    # Return packages needed to be installed and removed during
    # Autoinstallation to insure module has all needed software
    # installed.
    # @return [Hash] with 2 lists.
    def AutoPackages
      { "install" => ["pacemaker-mgmt", "csync2", "pacemaker"], "remove" => [] }
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
    publish :variable => :use_mgmtd, :type => "boolean"
    publish :variable => :secauth, :type => "boolean"
    publish :variable => :threads, :type => "string"
    publish :variable => :bindnetaddr1, :type => "string"
    publish :variable => :mcastaddr1, :type => "string"
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
    publish :variable => :memberaddr1, :type => "list <string>"
    publish :variable => :memberaddr2, :type => "list <string>"
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
