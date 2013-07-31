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

# File:	clients/cluster_proposal.ycp
# Package:	Configuration of cluster
# Summary:	Proposal function dispatcher.
# Authors:	Cong Meng <cmeng@novell.com>
#
# $Id: cluster_proposal.ycp 41350 2007-10-10 16:59:00Z dfiser $
#
# Proposal function dispatcher for cluster configuration.
# See source/installation/proposal/proposal-API.txt
module Yast
  class ClusterProposalClient < Client
    def main

      textdomain "cluster"

      Yast.import "Cluster"
      Yast.import "Progress"

      # The main ()
      Builtins.y2milestone("----------------------------------------")
      Builtins.y2milestone("Cluster proposal started")

      @func = Convert.to_string(WFM.Args(0))
      @param = Convert.to_map(WFM.Args(1))
      @ret = {}

      # create a textual proposal
      if @func == "MakeProposal"
        @proposal = ""
        @warning = nil
        @warning_level = nil
        @force_reset = Ops.get_boolean(@param, "force_reset", false)

        if @force_reset || !Cluster.ProposalValid
          Cluster.SetProposalValid(true)
          @progress_orig = Progress.set(false)
          Cluster.Read
          Progress.set(@progress_orig)
        end
        @sum = Cluster.Summary
        @proposal = Ops.get_string(@sum, 0, "")

        @ret = {
          "preformatted_proposal" => @proposal,
          "warning_level"         => @warning_level,
          "warning"               => @warning
        }
      # run the module
      elsif @func == "AskUser"
        @stored = Cluster.Export
        @seq = Convert.to_symbol(
          WFM.CallFunction("cluster", [path(".propose")])
        )
        Cluster.Import(@stored) if @seq != :next
        Builtins.y2debug("stored=%1", @stored)
        Builtins.y2debug("seq=%1", @seq)
        @ret = { "workflow_sequence" => @seq }
      # create titles
      elsif @func == "Description"
        @ret = {
          # Rich text title for Cluster in proposals
          "rich_text_title" => _(
            "Cluster"
          ),
          # Menu title for Cluster in proposals
          "menu_title"      => _(
            "&Cluster"
          ),
          "id"              => "cluster"
        }
      # write the proposal
      elsif @func == "Write"
        Cluster.Write
      else
        Builtins.y2error("unknown function: %1", @func)
      end

      # Finish
      Builtins.y2debug("ret=%1", @ret)
      Builtins.y2milestone("Cluster proposal finished")
      Builtins.y2milestone("----------------------------------------")
      deep_copy(@ret) 

      # EOF
    end
  end
end

Yast::ClusterProposalClient.new.main
