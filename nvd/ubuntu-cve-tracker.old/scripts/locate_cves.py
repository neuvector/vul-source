#!/usr/bin/env python3

# Author: Marc Deslauriers <marc.deslauriers@ubuntu.com>
# Author: Steve Beattie <steve.beattie@canonical.com>
# Copyright (C) 2014-2022 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# This script will load all known CVE from UCT, and then will parse the
# mailbox files specified on the command line to identify CVEs that are
# unknown.

import argparse
import mailbox
import os
import re
import sys

import cve_lib

parser = argparse.ArgumentParser(description='A script to find unknown CVEs in email')
parser.add_argument("-d", "--debug", help="Enable debug reporting", action='store_true')
parser.add_argument('mailbox', type=str, nargs='+',  help='one or more mailboxes to search (mbox or MailDir)')
args = parser.parse_args()

def debug(message):
    global args

    if args.debug:
        print("DEBUG: %s" % message, file=sys.stderr)

cve_pat = re.compile(r'CVE-\d\d\d\d-\d{4,7}')

# Load a list of known CVEs from the tracker
known_cves = []

check_dirs = [cve_lib.active_dir, cve_lib.retired_dir, cve_lib.ignored_dir]

for dir in check_dirs:
    cve_files = [elem for elem in os.listdir(dir) \
                if re.match('^CVE-\d+-(\d|N)+$', elem)]

    known_cves += cve_files

ignored = cve_lib.parse_CVEs_from_uri('%s/not-for-us.txt' % cve_lib.ignored_dir)
known_cves += ignored

for mbox_file in args.mailbox:
    print("Searching mail file: %s\n" % mbox_file)
    if not os.path.exists(mbox_file):
        os.write(sys.stderr.fileno(), "Could not open file: %s\n" % mbox_file)
        continue

    if os.path.isfile(mbox_file):
        messages = mailbox.mbox(mbox_file)
    else:
        # assume maildir
        messages = mailbox.Maildir(mbox_file, factory=None)

    for message in messages:
        subject = message['subject']
        date = message['date']
        if message.is_multipart():
            body = ""
            try:
                for bodies in message.walk():
                    if bodies.get_content_type().startswith('text/'):
                        body += bodies.get_payload(decode=True).decode(errors='replace')
            except Exception as e:
                debug(print(e))
                pass
        else:
            body = message.get_payload(decode=True).decode(errors='replace')

        patterns = cve_pat.findall(body)
        if patterns:
            matches = list(set(patterns))
            if matches:
                debug("Found: %s in message %s" % (matches, subject))
                for cve in matches:
                    if cve not in known_cves:
                        print("Couldn't find %s in tracker!" % cve)
                        print("Message date:    %s" % date)
                        if subject:
                            print("Message subject: %s\n" % subject)
                        else:
                            print("Message subject: <empty>\n")
