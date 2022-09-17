#!/usr/bin/python3
#
# Authors:
#   Jamie Strandboge <jamie@canonical.com>
#   Steve Beattie <steve.beattie@canonical.com>
# Copyright (C) 2016-2020 Canonical, Ltd.
# License: GPLv3
#
# This script is used to do update the bug status for
# security signoffs in the kernel SRU process. See
# https://wiki.ubuntu.com/Kernel/kernel-sru-workflow for details
#
# TODO: add a --message option to include a comment on the bug report?

from __future__ import print_function

import argparse
import sys

import lpl_common

rc = 0
lp = lpl_common.connect()

status_signed_off = "Fix Released"
status_no_security = "Invalid"
status_unsigned = "In Progress"


def debug(msg):
    global args
    if args.debug:
        print(msg, file=sys.stderr)


parser = argparse.ArgumentParser(description="kernel security signoff tool")
parser.add_argument("-d", "--debug", help="Report debug information", action="store_true")
parser.add_argument("-f", "--force", help="Force changing state even if task state is not correct", action="store_true")
parser.add_argument("-n", "--no-change", help="Don't actually adjust bug state", action="store_true")
parser.add_argument(
    "-i", "--no-security", help="Kernel does not contain security fixes, signoff to updates only", action="store_true"
)
parser.add_argument("bugs", help="launchpad bugs to signoff on", nargs="+")
args = parser.parse_args()

for bugno in args.bugs:
    if bugno.startswith("#"):
        bugno = bugno[1:]
    debug("Looking up bug: %s" % bugno)
    bug = lp.bugs[bugno]

    task = None
    for t in bug.bug_tasks:
        if t.bug_target_name == "kernel-sru-workflow/security-signoff":
            task = t
            break

    if not task:
        print("[%s] Unable to find signoff task, skipping!" % bugno)
        rc = 1
        continue

    debug("Signoff task for bug %s found, status is %s." % (bugno, task.status))

    if not task.status == status_unsigned:
        if not args.force:
            print("[%s] %s has status %s, skipping." % (bugno, t.bug_target_display_name, task.status))
            print("(Use --force to override)")
            continue
        else:
            print("[%s] (Warning) %s has status %s" % (bugno, t.bug_target_display_name, task.status))

    if not args.no_change:
        if args.no_security:
            update_status = status_no_security
        else:
            update_status = status_signed_off
        debug("[%s] attempting to sign off on task with %s" % (bugno, update_status))
        task.status = update_status
        lpl_common.save(task)
        print('[%s] "%s" signed off: %s' % (bugno, task.bug.title, update_status))

sys.exit(rc)
