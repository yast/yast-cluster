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
  module ClusterWizardsInclude
    def initialize_cluster_wizards(include_target)
      Yast.import "UI"

      textdomain "cluster"

      Yast.import "Sequencer"
      Yast.import "Wizard"

      Yast.include include_target, "cluster/complex.rb"
      Yast.include include_target, "cluster/dialogs.rb"
      Yast.include include_target, "cluster/common.rb"

      @Aliases = {
        "communication" => lambda { CommunicationDialog() },
        "security"      => lambda { SecurityDialog() },
        "csync2"        => lambda { Csync2Dialog() },
        "conntrack"     => lambda { ConntrackDialog() },
        "service"       => lambda { ServiceDialog() }
      }
    end

    def TabSequence
      anywhere = { :abort => :abort, :next => :next }
      Builtins.foreach(@DIALOG) do |key|
        anywhere = Builtins.add(
          anywhere,
          Builtins.symbolof(Builtins.toterm(key)),
          key
        )
      end

      sequence = { "ws_start" => Ops.get(@DIALOG, 0, "") }
      Builtins.foreach(@DIALOG) do |key|
        sequence = Builtins.add(sequence, key, anywhere)
      end

      # UI initialization
      Wizard.OpenTreeNextBackDialog

      tree = []
      Builtins.foreach(@DIALOG) do |key|
        tree = Wizard.AddTreeItem(
          tree,
          Ops.get_string(@PARENT, key, ""),
          Ops.get_string(@NAME, key, ""),
          key
        )
      end

      Wizard.CreateTree(tree, "Cluster")

      # Buttons redefinition
      Wizard.SetNextButton(:next, Label.FinishButton)

      if UI.WidgetExists(Id(:wizardTree))
        Wizard.SetBackButton(:help_button, Label.HelpButton)
        Wizard.SetAbortButton(:abort, Label.CancelButton)
      else
        UI.WizardCommand(term(:SetNextButtonLabel, Label.FinishButton))
        UI.WizardCommand(term(:SetAbortButtonLabel, Label.CancelButton))
        Wizard.HideBackButton
      end

      Wizard.SelectTreeItem(Ops.get_string(sequence, "ws_start", ""))

      ret = Sequencer.Run(@Aliases, sequence)
      Wizard.CloseDialog
      deep_copy(ret)
    end

    def FirstRunSequence
      sequence = {
        "ws_start"      => "communication",
        "communication" => {
          :next  => "security",
          :back  => "communication",
          :abort => :abort
        },
        "security"      => {
          :next  => "csync2",
          :back  => "communication",
          :abort => :abort
        },
        "csync2"        => {
          :next  => "conntrack",
          :back  => "security",
          :abort => :abort
        },
        "conntrack"     => {
          :next  => "service",
          :back  => "csync2",
          :abort => :abort
        },
        "service"       => {
          :next  => :next,
          :back  => "conntrack",
          :abort => :abort
        }
      }

      ret = Sequencer.Run(@Aliases, sequence)

      deep_copy(ret)
    end

    def MainSequence
      if Cluster.firstrun
        return FirstRunSequence()
      else
        return TabSequence()
      end
    end

    # Whole configuration of cluster
    # @return sequence result
    def ClusterSequence
      aliases = {
        "read"  => [lambda { ReadDialog() }, true],
        "main"  => lambda { MainSequence() },
        "write" => [lambda { WriteDialog() }, true]
      }

      sequence = {
        "ws_start" => "read",
        "read"     => { :abort => :abort, :next => "main" },
        "main"     => { :abort => :abort, :next => "write" },
        "write"    => { :abort => :abort, :next => :next }
      }

      Wizard.CreateDialog

      ret = Sequencer.Run(aliases, sequence)

      UI.CloseDialog
      deep_copy(ret)
    end

    # Whole configuration of cluster but without reading and writing.
    # For use with autoinstallation.
    # @return sequence result
    def ClusterAutoSequence
      # Initialization dialog caption
      caption = _("Cluster Configuration")
      # Initialization dialog contents
      contents = Label(_("Initializing..."))

      Wizard.CreateDialog
      Wizard.SetContentsButtons(
        caption,
        contents,
        "",
        Label.BackButton,
        Label.NextButton
      )

      ret = MainSequence()

      UI.CloseDialog
      deep_copy(ret)
    end
  end
end
