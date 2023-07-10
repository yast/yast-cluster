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

# File:	include/cluster/wizards.ycp
# Package:	Configuration of cluster
# Summary:	Wizards definitions
# Authors:	Cong Meng <cmeng@novell.com>
#
# $Id: wizards.ycp 27914 2006-02-13 14:32:08Z locilka $
module Yast
  module ClusterCommonInclude
    def initialize_cluster_common(include_target)
      textdomain "cluster"

      Yast.import "Label"
      Yast.import "Wizard"
      Yast.import "Cluster"
      Yast.import "Popup"
      Yast.import "CWM"
      Yast.import "CWMFirewallInterfaces"

      @DIALOG = ["communication", "corosyncqdevice", "security", "csync2", "conntrack", "service"]

      @PARENT = {}

      @NAME = {
        "communication"    => _("Communication Channels"),
        "corosyncqdevice"  => _("Corosync Qdevice"),
        "security"         => _("Security"),
        "service"          => _("Service"),
        "csync2"           => _("Configure Csync2"),
        "conntrack"        => _("Configure conntrackd")
      }
    end

    def myHelp(help)
      UI.OpenDialog(
        Opt(:decorated),
        HBox(
          VSpacing(16),
          VBox(
            HSpacing(60),
            VSpacing(0.5),
            RichText(Ops.get_string(@HELPS, help, "")),
            VSpacing(1.5),
            PushButton(Id(:ok), Opt(:default, :key_F10), Label.OKButton)
          )
        )
      )

      UI.SetFocus(Id(:ok))
      UI.UserInput
      UI.CloseDialog

      nil
    end

    def my_SetContents(conf, contents)
      contents = deep_copy(contents)
      Wizard.SetContents(
        Ops.add("Cluster - ", Ops.get_string(@NAME, conf, "")),
        contents,
        Ops.get_string(@HELPS, conf, ""),
        true,
        true
      )

      UI.SetFocus(Id(:wizardTree)) if UI.WidgetExists(Id(:wizardTree))

      nil
    end

    def valid_number?(num)
      /^\d+$/.match?(num)
    end

    def valid_port_number?(port)
      valid_number?(port) && port.to_i.between?(0, 65535)
    end

    def valid_nodeid?(nodeid)
      valid_number?(nodeid) && nodeid.to_i > 0
    end
  end
end
