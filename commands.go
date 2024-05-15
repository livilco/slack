// mautrix-slack - A Matrix-Slack puppeting bridge.
// Copyright (C) 2022 Tulir Asokan
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"fmt"
	"net/url"
	"strings"

	"maunium.net/go/mautrix/bridge/commands"
)

type WrappedCommandEvent struct {
	*commands.Event
	Bridge *SlackBridge
	User   *User
	Portal *Portal
}

func (br *SlackBridge) RegisterCommands() {
	proc := br.CommandProcessor.(*commands.Processor)
	proc.AddHandlers(
		cmdPing,
		cmdLoginPassword,
		cmdLoginToken,
		cmdLogout,
		cmdLogoutAll,
		cmdSyncTeams,
		cmdDeletePortal,
	)
}

func wrapCommand(handler func(*WrappedCommandEvent)) func(*commands.Event) {
	return func(ce *commands.Event) {
		user := ce.User.(*User)
		var portal *Portal
		if ce.Portal != nil {
			portal = ce.Portal.(*Portal)
		}
		br := ce.Bridge.Child.(*SlackBridge)
		handler(&WrappedCommandEvent{ce, br, user, portal})
	}
}

var cmdPing = &commands.FullHandler{
	Func: wrapCommand(fnPing),
	Name: "ping",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Check which teams you're currently signed into",
	},
}

func fnPing(ce *WrappedCommandEvent) {
	if len(ce.User.Teams) == 0 {
		ce.Reply("You are not signed in to any Slack teams.")
		return
	}
	var text strings.Builder
	text.WriteString("You are signed in to the following Slack teams:\n")
	for _, team := range ce.User.Teams {
		teamInfo := ce.Bridge.DB.TeamInfo.GetBySlackTeam(team.Key.TeamID)
		text.WriteString(fmt.Sprintf("%s - %s - %s.slack.com", teamInfo.TeamID, teamInfo.TeamName, teamInfo.TeamDomain))
		if team.RTM == nil {
			text.WriteString(" (Error: not connected to Slack)")
		}
		text.WriteRune('\n')
	}
	ce.Reply(text.String())
}

var cmdLoginPassword = &commands.FullHandler{
	Func: wrapCommand(fnLoginPassword),
	Name: "login-password",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Link the bridge to a Slack account (legacy password login)",
		Args:        "<email> <domain> <password>",
	},
}

func fnLoginPassword(ce *WrappedCommandEvent) {
	if len(ce.Args) != 3 {
		ce.Reply("**Usage**: $cmdprefix login-password <email> <domain> <password>")
		return
	}

	if ce.User.IsLoggedInTeam(ce.Args[0], ce.Args[1]) {
		ce.Reply("%s is already logged in to team %s", ce.Args[0], ce.Args[1])
		return
	}

	user := ce.Bridge.GetUserByMXID(ce.User.MXID)
	err := user.LoginTeam(ce.Args[0], ce.Args[1], ce.Args[2])
	if err != nil {
		ce.Reply("Failed to log in as %s for team %s: %v", ce.Args[0], ce.Args[1], err)
		return
	}

	ce.Reply("Successfully logged into %s for team %s", ce.Args[0], ce.Args[1])
	ce.Reply("Note: with legacy password login, your conversations will only be bridged once messages arrive in them through Slack. Use the `login-token` command if you want your joined conversations to be immediately bridged (you don't need to logout first).")
}

var cmdLoginToken = &commands.FullHandler{
	Func: wrapCommand(fnLoginToken),
	Name: "login-token",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Link the bridge to a Slack account",
		Args:        "<token> <cookieToken>",
	},
}

func fnLoginToken(ce *WrappedCommandEvent) {
	if len(ce.Args) != 2 {
		ce.Reply("**Usage**: $cmdprefix login-token <token> <cookieToken>")
		return
	}

	cookieToken, _ := url.PathUnescape(ce.Args[1])

	user := ce.Bridge.GetUserByMXID(ce.User.MXID)
	info, err := user.TokenLogin(ce.Args[0], cookieToken)

	if err != nil {
		user.log.Errorfln("Failed to log in with token: %v\n", err)
		ce.Reply("Failed to log in with token: %v", err)
	} else {
		user.log.Debugfln("Successfully logged into %s for team %s\n", info.UserEmail, info.TeamName)
		ce.Reply("Successfully logged into %s for team %s", info.UserEmail, info.TeamName)
		teamInfo := ce.Bridge.DB.TeamInfo.GetBySlackTeam(info.TeamID)

		// Find any other users associated with the same slack account
		// and log them out
		for _, otherUser := range ce.Bridge.usersByMXID {
			if otherUser.MXID == ce.User.MXID {
				continue
			}
			if otherUser.IsLoggedInTeam(info.UserEmail, info.TeamName) {
				otherUser.log.Debugfln("Trying to logout the other session for: %s\n", otherUser.MXID)
				team := otherUser.bridge.DB.UserTeam.GetBySlackDomain(otherUser.MXID, info.UserEmail, teamInfo.TeamDomain)
				otherUser.log.Debugfln("Found team %+v", team)

				if team != nil {
					otherUser.log.Debugfln("Found team %+v", team)
					otherUser.log.Debugfln("Logging out session on another account (%s) from team %s...\n", otherUser.MXID, info.TeamName)
					ce.Reply("Logging out session on another account (%s) from team %s", otherUser.MXID, info.TeamName)

					// TODO: ensure user team is disconnected when it is logged out
					err := ce.User.disconnectTeam(team)
					if err != nil {
						ce.Reply("Error disconnecting from Slack: %v", err)
						continue
					}

					err = otherUser.LogoutUserTeam(team)
					if err != nil {
						otherUser.log.Errorfln("Error logging out: %v\n", err)
						ce.Reply("Error logging out: %v", err)
					} else {
						otherUser.log.Debugfln("Logged out successfully\n")
						ce.Reply("Other session logged out successfully for %s", otherUser.MXID)
					}
				} else {
					otherUser.log.Warnfln("Failed to find team %s and email %s in database for user %s", info.TeamName, info.UserEmail, otherUser.MXID)
				}
			}
		}
	}
}

var cmdLogout = &commands.FullHandler{
	Func: wrapCommand(fnLogout),
	Name: "logout",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Unlink the bridge from your Slack account.",
		Args:        "<email> <domain>",
	},
	RequiresLogin: true,
}

func fnLogout(ce *WrappedCommandEvent) {
	if len(ce.Args) != 2 {
		ce.Reply("**Usage**: $cmdprefix logout <email> <domain>")

		return
	}
	domain := strings.TrimSuffix(ce.Args[1], ".slack.com")
	userTeam := ce.User.bridge.DB.UserTeam.GetBySlackDomain(ce.User.MXID, ce.Args[0], domain)

	// TODO: ensure user team is disconnected when it is logged out
	err := ce.User.disconnectTeam(userTeam)
	if err != nil {
		ce.Reply("Error disconnecting from Slack: %v", err)
		return
	}

	err = ce.User.LogoutUserTeam(userTeam)
	if err != nil {
		ce.Reply("Error logging out: %v", err)
	} else {
		ce.Reply("Logged out successfully.")
	}
}

var cmdLogoutAll = &commands.FullHandler{
	Func: wrapCommand(fnLogoutAll),
	Name: "logout-all",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionAuth,
		Description: "Unlink the bridge from all your Slack accounts.",
	},
}

func fnLogoutAll(ce *WrappedCommandEvent) {
	for _, team := range ce.User.Teams {
		err := ce.User.disconnectTeam(team)
		if err != nil {
			ce.Reply("Error disconnecting from Slack: %v", err)
			return
		}

		err = ce.User.LogoutUserTeam(team)
		if err != nil {
			ce.Reply("Error logging out: %v", err)
			return
		} else {
			ce.Reply("Logged out successfully.")
		}
	}
}

var cmdSyncTeams = &commands.FullHandler{
	Func: wrapCommand(fnSyncTeams),
	Name: "sync-teams",
	Help: commands.HelpMeta{
		Section:     commands.HelpSectionGeneral,
		Description: "Synchronize team information and channels from Slack into Matrix",
	},
	RequiresLogin: true,
}

func fnSyncTeams(ce *WrappedCommandEvent) {
	for _, team := range ce.User.Teams {
		ce.User.UpdateTeam(team, true)
	}
	ce.Reply("Done syncing teams.")
}

var cmdDeletePortal = &commands.FullHandler{
	Func:           wrapCommand(fnDeletePortal),
	Name:           "delete-portal",
	RequiresPortal: true,
}

func fnDeletePortal(ce *WrappedCommandEvent) {
	ce.Portal.delete()

	ce.Bridge.cleanupRoom(ce.Portal.MainIntent(), ce.Portal.MXID, false, ce.Log)
	ce.Log.Infofln("Deleted portal")
}
