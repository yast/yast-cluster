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

# File:	include/cluster/complex.ycp
# Package:	Configuration of cluster
# Summary:	Dialogs definitions
# Authors:	Cong Meng <cmeng@novell.com>
#
# $Id: complex.ycp 41350 2007-10-10 16:59:00Z dfiser $
module Yast
  module ClusterComplexInclude
    def initialize_cluster_complex(include_target)
      Yast.import "UI"

      textdomain "cluster"

      Yast.import "Label"
      Yast.import "Popup"
      Yast.import "Wizard"
      Yast.import "Confirm"
      Yast.import "Cluster"


      Yast.include include_target, "cluster/helps.rb"
    end

    # Return a modification status
    # @return true if data was modified
    def Modified
      Cluster.Modified
    end

    def ReallyAbort
      #    return !Cluster::Modified() || Popup::ReallyAbort(true);
      Popup.ReallyAbort(true)
    end

    def PollAbort
      UI.PollInput == :abort
    end

    # Read settings dialog
    # @return `abort if aborted and `next otherwise
    def ReadDialog
      Wizard.RestoreHelp(Ops.get_string(@HELPS, "read", ""))
      # Cluster::SetAbortFunction(PollAbort);
      return :abort if !Confirm.MustBeRoot
      ret = Cluster.Read
      ret ? :next : :abort
    end

    # Write settings dialog
    # @return `abort if aborted and `next otherwise
    def WriteDialog
      Wizard.RestoreHelp(Ops.get_string(@HELPS, "write", ""))
      # Cluster::SetAbortFunction(PollAbort);
      ret = Cluster.Write
      ret ? :next : :abort
    end
  end
end
