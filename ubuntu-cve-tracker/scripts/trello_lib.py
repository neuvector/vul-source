#!/usr/bin/env python3
# Author: Mark Morlino <mark.morlino@canonical.com>
# Copyright (C) 2005-2019 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Command-line tool and python module for managing trello cards

import argparse
import os
import re
import requests
import sys
import yaml

# there are a confusing number of trello modules
# pip install py-trello to satisfy this
from trello import TrelloClient
from pprint import pprint
import configparser

class TrelloHelper:
    def __init__(self, api_key, token, board_name, exclude_lanes=[], debug=False):
        self.client = TrelloClient(api_key=api_key, token=token)
        self.boards = self.client.list_boards()
        self.dbg = debug
        for b in self.boards:
            if(b.name == board_name):
                self.board = b
        assert hasattr(self, 'board'), "Unable to set board, \"%s\" not found" % board_name
        self.members = self.board.all_members()
        self.labels = self.board.get_labels()
        self.lanes = self.board.list_lists()
        self.exclude_lanes = exclude_lanes

    def set_lane(self, name):
        for l in self.lanes:
            if(l.name == name):
                self.debug("Setting lane: %s" % name)
                self.lane = l
        assert hasattr(self, 'lane'), "Unable to set lane, \"%s\" not found" % name
    
    def set_card(self, card_id):
        self.card = self.client.get_card(card_id)

    def list_boards(self):
        self.debug("Listing Boards")
        for b in self.boards:
            self.debug("%s %s %s" % (b.id, b.url, b.name))
            yield b

    def list_lanes(self):
        self.debug("Listing Lanes")
        for l in self.lanes:
            self.debug("%s %s" % (l.id, l.name))
            yield l

    def list_cards(self):
        self.debug("Listing Cards")
        for c in self.lane.list_cards():
            self.debug("%s %s %s" % (c.id, c.url, c.name))
            yield c

    def list_members(self):
        if hasattr(self, 'card'):
            self.debug("Listing Members of %s card" % self.card.name)
            for cm in self.card.member_id:
                for bm in self.members:
                    if cm == bm.id:
                        self.debug("%s %s" % (bm.id, bm.username))
                        yield bm
        else:
            self.debug("Listing Members of %s board" % self.board.name)
            for bm in self.members:
                self.debug("%s %s" % (bm.id, bm.username))
                yield bm
    
    def list_labels(self):
        if hasattr(self, 'card'):
            self.debug("Listing Labels for card: %s" % self.card.name)
            for cl in self.card.labels:
                self.debug("%s %s" % (cl.id, cl.name))
                yield cl
        else:
            self.debug("Listing Labels for board: %s" % self.board.name)
            for bl in self.labels:
                self.debug("%s %s" % (bl.id, bl.name))
                yield bl

    def list_checklists(self):
        if hasattr(self, 'card'):
            self.debug("Listing checklists for card: %s" % self.card.name)
            for cl in self.card.checklists:
                self.debug("%s %s" % (cl.id, cl.name))
                for i in cl.items:
                    self.debug("  %s %s %s" % (i['id'], i['checked'],i['name']))
                yield cl

    def create_card(self, name, desc=None):
        self.debug("Create card %s\n%s" % (name, desc))
        card = self.lane.add_card(name, desc)
        return card.id

    def create_checklist(self, title, items):
        if hasattr(self, 'card'):
            self.debug("Adding checklist %s for card %s, items are %s" % (title, self.card.name, items))
            self.card.add_checklist(title, items)

    def find_cards(self, search_text, include_closed = False):
        self.debug("""Excluding Lanes: %s""" % self.exclude_lanes)
        for l in self.lanes:
            if not l.name in self.exclude_lanes:
                #self.debug("""Searching for cards matching "%s" in lane "%s" """ % (search_text, l.name))
                for c in l.list_cards():
                    #self.debug("""    search for: "%s" in name: "%s" desc: "%s..." """ % (search_text, c.name, c.desc[0:30]))
                    if c.name.find(search_text) >= 0 or c.desc.find(search_text) >= 0:
                        if include_closed or c.closed == include_closed:
                            yield c

    def assign_card(self, member_names):
        self.debug("Assign '%s'" % member_names)
        if hasattr(self, 'card'):
            for nm in member_names:
                for bm in self.members:
                    if nm == bm.username:
                        if bm.id in self.card.member_id:
                            self.debug("%s (%s) already assigned to card %s" % (nm, bm.id, self.card))
                        else:
                            self.debug("Assign card %s to %s (%s)" % (self.card, nm, bm.id))
                            self.card.assign(bm.id)

    def unassign_card(self, member_names=None):
        self.debug("Unassign '%s'" % member_names)
        if hasattr(self, 'card'):
            if len(member_names) == 0:
                for cm in self.card.member_id:
                    self.debug("Unassign card %s from %s" % (self.card, cm))
                    self.card.unassign(cm)
            else:
                for nm in member_names:
                    for bm in self.members:
                        if nm == bm.username:
                            if bm.id in self.card.member_id:
                                self.debug("Unassign card %s from %s" % (self.card, bm.id))
                                self.card.unassign(bm.id)
                            else:
                                self.debug("%s (%s) not assigned to card %s" % (nm, bm.id, self.card))

    def label_card(self, labels):
        if hasattr(self, 'card'):
            for l in self.labels:
                if l.name in labels:
                    self.debug("label card %s as %s (%s)" % (self.card, l.name, l.id))
                    self.card.add_label(l)

    def move_card(self, lane_name):
        if hasattr(self, 'card'):
            for l in self.board.list_lists():
                if l.name == lane_name:
                    self.card.change_list(l.id)

    def archive_card(self):
        if hasattr(self, 'card'):
            self.card.set_closed(True)

    def delete_card(self):
        if hasattr(self, 'card'):
            self.card.set_closed(True)

    def debug(self, m):
        if self.dbg:
            print(m)

def environ_or_config(key, config, required=True):
    """Mapping for argparse to supply optional default from $ENV."""
    if os.environ.get(key):
        return {'default': os.environ.get(key)}
    elif key in config['DEFAULT'].keys():
        return {'default': config['DEFAULT'][key]}
    else:
        return {'required': required}


def get_args(config):
    parser = argparse.ArgumentParser()

    parser.add_argument('--debug', action='store_true', default=None, help="enable debugging output")

    parser.add_argument('--key', help="Trello API key",
                        **environ_or_config('TRELLO_KEY', config))
    parser.add_argument('--token', help="Trello OAuth token",
                        **environ_or_config('TRELLO_TOKEN', config))
    parser.add_argument('--board', help="Trello board identifier",
                        **environ_or_config('TRELLO_BOARD', config))
    parser.add_argument('--lane', help="Trello lane/list identifier",
                        **environ_or_config('TRELLO_LANE', config, False))
    parser.add_argument('--exclude_lanes', help="Comma separated list of lanes to exclude from searches",
                        **environ_or_config('TRELLO_EXCLUDE_LANES', config, False))

    parser.add_argument('--config', action='store_true', help="Create/update ~/.trello.conf file", required=False)

    parser.add_argument('--list', help='List Trello "<boards|lanes|cards|members|labels>" associated with a board or a card')
    parser.add_argument('--find', '--search', help='Find Trello card by name/title "<name>"')
    parser.add_argument('--new', nargs=2, help='Create new Trello card "<name>" "<description>" (requires --lane <lane_name>)')

    parser.add_argument('--card', help='Card ID')
    parser.add_argument('--show', action='store_true', help='Print details for an existing Trello card (requires --card <card_id>)')
    parser.add_argument('--move', help='Move existing Trello card "<new_lane_name>" (requires --card <card_id>)')
    parser.add_argument('--assign', nargs='+', help='Assign existing Trello card "<new_member_name>" (requires --card <card_id>)')
    parser.add_argument('--unassign', nargs='*', default=None, help='Unassign existing Trello card "[member_name]" (requires --card <card_id>)')
    parser.add_argument('--label', nargs='+', help='Add label to existing Trello card "<new_label1> [new_label2] ..." (requires --card <card_id>)')
    parser.add_argument('--checklist', help='Add checklist (named Tasks) to existing Trello card <item1,item2,item3> (requires --card <card_id>)')
    parser.add_argument('--archive', help='Close existing Trello card (requires --card <card_id>)')
    parser.add_argument('--delete', help='Delete existing Trello card (requires --card <card_id>)')
    return parser.parse_args()

def get_config(d='~', f='.trello.conf'):
    c = configparser.ConfigParser()
    c.optionxform=str
    c.read(os.path.join(os.path.expanduser(d), f))
    return c

def main():

    args = get_args(get_config())
    #pprint(vars(args))
 
    if args.config:
        config = configparser.ConfigParser()
        config.optionxform=str
        config['DEFAULT'] = {'TRELLO_KEY': args.key,
                             'TRELLO_TOKEN': args.token,
                             'TRELLO_BOARD': args.board,
                             'TRELLO_EXCLUDE_LANES': args.exclude_lanes }
        config.write(open(os.path.join(os.path.expanduser("~"), ".trello.conf"), "w+"))

    if (args.move or args.assign or args.unassign or args.show or args.label or args.checklist or args.archive or args.delete) and args.card is None:
        print("--card <card_id> is required with --show, --move, --assign, --unassign, --archive, --checklist, --delete and --label")
        quit()
        
    list_modes = ['boards', 'lanes', 'cards', 'members', 'labels', 'checklists']
    if args.list:
        if args.list not in list_modes:
            print("Invalid option after --list, should be one of %s" % list_modes)
            quit()
        if (args.list == 'cards' and args.lane is None):
            print("--lane <lane_name> is required with --list cards")
            quit()
        
    if args.exclude_lanes:
        args.exclude_lanes = args.exclude_lanes.split(',')

    trello = TrelloHelper(args.key, args.token, args.board, args.exclude_lanes, args.debug)

    if args.card:
        trello.set_card(args.card)

    if args.lane:
        trello.set_lane(args.lane)

    if args.list:
        if args.list == 'boards':
            results = trello.list_boards()
        elif args.list == 'lanes':
            results = trello.list_lanes()
        elif args.list == 'cards':
           results = trello.list_cards()
        elif args.list == 'members':
            results = trello.list_members()
        elif args.list == 'labels':
            results = trello.list_labels()
        elif args.list == 'checklists':
            results = trello.list_checklists()
        for r in results:
            print(r.id)

    if args.find:
        trello.debug("Searching for '%s' in card names and descriptions" % args.find)
        for card in trello.find_cards(args.find):
            trello.debug("{} -> {} -> {} -> {}\n{}\n{}".format(card.board.name, card.trello_list.name, card.id, card.name, card.url, card.desc))
            print(card.id)

    if args.show:
        print("{} -> {} -> {} -> {}\n{}\n{}\n{}".format(trello.card.board.name, trello.card.trello_list.name, trello.card.id, trello.card.name, trello.card.url, trello.card.desc, trello.card.checklists))

    if args.new:
        trello.debug("Creating new card on board %s in lane %s with name '%s'" % (args.board, args.lane, args.new[0]))
        print(trello.create_card(args.new[0], args.new[1]))

    if args.move:
        trello.debug("Moving card on board '%s' with id '%s' to lane '%s'" % (args.board, args.card, args.move))
        trello.move_card(args.card, args.move)

    if args.assign:
        trello.debug("Assigning card on board '%s' with id '%s' to member '%s'" % (args.board, args.card, args.assign))
        trello.assign_card(args.assign)

    if args.unassign:
        trello.debug("Unassigning card on board '%s' with id '%s' from member '%s'" % (args.board, args.card, args.assign))
        trello.unassign_card(args.unassign)

    if args.label:
        trello.debug("Labeling card on board '%s' with id '%s' with label '%s'" % (args.board, args.card, args.label))
        trello.label_card(args.label)

    if args.archive:
        trello.debug("closing card with id '%s'" % args.card)
        trello.archive_card()

    if args.delete:
        trello.debug("closing card with id '%s'" % args.card)
        trello.delete_card()

if __name__ == "__main__":
    main()
