#!/usr/bin/env python2

# Copyright (C) 2017 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 2 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#

from __future__ import print_function

import sqlite3, sys, subprocess, os, argparse, smtplib
from email.utils import parseaddr
from email.mime.text import MIMEText
from datetime import datetime, timedelta
import os.path

notifydb = '~/notify/notification.db'
reportdir = '~/notify/'
scriptdir = '~/reviewed/'
uctdir = '~/git-pulls/cve-tracker/'
ubutable = './scripts/ubuntu-table'
utparms = ' --unmask-needed -s -E --only-release xenial'
valid_freq = {'daily', 'weekly'}
valid_sev = ['negligible', 'low', 'medium', 'high', 'critical']
valid_reptype = {'full', 'onchange'}
fromaddr = 'security@ubuntu.com'
mail_footer = "\nIf you no longer want to receive these reports, let the Ubuntu security team know at security@ubuntu.com."

def print_usage():
    '''Print helpful information'''
    print("notify COMMAND [OPTIONS] ")
    print()
    print("COMMAND:")
    print("init	Create and initialize the databases")
    print("help	Print this helpful information")
    print("add	Add a new package subscription")
    print("del	Delete a package subscription")
    print("list	Print out the subscription database")
    print("report	Generate the reports")
    print("mail	Mail out available reports")
    print()
    print("OPTIONS:")
    print("-n <NUMBER>")
    print("-p <PACKAGE>")
    print("-e <EMAIL>")
    print("-s <SEVERITY>")
    print("-f <FREQUENCY>")
    print("-t <REPORT_TYPE>")
    print("-r <REPORT DIRECTORY>")
    print("-b <FULL PATH OF DB FILE>")
    print("--debug")

def cmd_help():
    '''Print helpful information'''
    print_usage()

def cmd_init():
    '''Create the databases for initial deployment'''
    tt = 'text'
    conn = sqlite3.connect(notifydb)
    c = conn.cursor()
    # Create table
    c.execute('CREATE TABLE subscription (address tt, package tt, severity tt, frequency tt, reptype tt)')
    # Insert test data
    c.execute("INSERT INTO subscription VALUES ('security@ubuntu.com', 'byobu', 'high', 'weekly', 'full')")
    # Commit the changes
    conn.commit()
    # Close the database
    conn.close()
    return True

def cmd_del():
    '''Delete a subscription from the database'''
    print("Deleting row ", rownum)
    if rownum <= 0:
        print("Bad record indicator!")
        return False
    # Connect to the database
    conn = sqlite3.connect(notifydb)
    c = conn.cursor()
    # Delete data
    try:
        c.execute('DELETE FROM subscription WHERE rowid=?', (rownum,))
    except sqlite3.IntegrityError:
        print("ERROR: Could not delete record", file=sys.stderr)
        conn.close()
        return False
    # Commit the changes
    conn.commit()
    # Close the database
    conn.close()
    print("Subscription deleted!")
    return True

def cmd_add():
    '''Add a subscription to the database'''
    addr = args.email
    pkg = args.package
    sev = args.severity
    freq = args.frequency
    rtype = args.report_type

    # TODO: add a check to see if the package is a valid source package
    # NOTE: there is not a huge amount of parameter validation done since
    # this script is expected to be called only by security team members
    # (DAC access for ubuntu-security on people.ubuntu.com)
    # who are not motivated to screw things up when they could just delete
    # the database instead
    # TODO: a duplicate check would be nice
    if addr == None or pkg == None:
        print("Email address and package must be specified", file=sys.stderr)
        print_usage()
        return
    if '@' not in parseaddr(addr)[1]:
        print("Email address parsing failure. Subscription not added.", file=sys.stderr)
        return
    if freq not in valid_freq:
        print("Warning: %s is not a valid frequency, defaulting to daily" % (freq), file=sys.stderr)
        freq = 'daily'
    if sev not in valid_sev:
        print("Warning: %s is not a valid severity, defaulting to medium" % (sev))
        sev = 'medium'
    if rtype not in valid_reptype:
        print("Warning: %s is not a valid type of report, defaulting to onchange" % (rtype), file=sys.stderr)
        rtype = 'onchange'
    # Connect to the database
    conn = sqlite3.connect(notifydb)
    c = conn.cursor()
    # Insert data
    try:
        c.execute('INSERT INTO subscription (address, package, severity, frequency, reptype) VALUES (?, ?, ?, ?, ?)', (addr, pkg, sev, freq, rtype,))
    except sqlite3.IntegrityError:
        print("ERROR: Could not add record", file=sys.stderr)
        conn.close()
        return False
    # Commit the changes
    conn.commit()
    # Close the database
    conn.close()
    print("Subscription successfully added!")
    return True

def cmd_list():
    '''List all of the subscriptions in the database'''

    # Connect to the database
    if args.debug:
        print(notifydb)
    conn = sqlite3.connect(notifydb)
    c = conn.cursor()
    c.execute('SELECT rowid, address, package, severity, frequency, reptype FROM subscription')
    all_rows = c.fetchall()
    print("ID     Package     Severity    Frequency  Report Type Subscriber")
    for col in all_rows:
        print(col[0], end=' ')
        format = '%12s'
        for x in range(2, 6):
            print(format % col[x], end=' ')
        print(col[1])
    # Close the database
    conn.close()
    return True

def gen_report(emailaddr, pkg, severity, reptype, repdate, dateLimit):
    '''Write the report using the given inputs'''
    # ubuntu-table has to be in the UCT directory to generate meaningful output
    rc = os.chdir(uctdir)
    myparms = " --omit-header"
    dateparms = " "
    if reptype == "onchange":
        dateparms = " --public-date " + dateLimit
    report_name = emailaddr + "." + repdate
    if args.debug:
        print(emailaddr, pkg, severity, reptype, '\n', report_name)
    pkgparm = " -p " + pkg
    priorityparms = " "
    gosev = False
    # Add the higher priorities
    for sev in valid_sev:
        if severity == sev:
            gosev = True
        if gosev:
            priorityparms += " --priority " + sev
    outputparms = " >> " + reportdir + report_name
    ubutablecmd = ubutable + pkgparm + utparms + priorityparms + myparms + dateparms + outputparms
    if args.debug:
        print(ubutablecmd)
    my_env = os.environ.copy()
    out = subprocess.call([ubutablecmd], env=my_env, shell=True)
    rc = os.chdir(origdir)
    return True

def cmd_report():
    '''Generate all of the required reports'''
    # Get all of the daily subscriptions and generate the records'''
    # If today is Wednesday, then get all of the weekly subscriptions'''
    # and generate the records'''
    # TODO: this would perform much better if it integrated cve_lib rather 
    # than calling ubuntu_table. However, there is no urgency in generating the
    # reports, so starting with this easy method first
    # Even calling ubutable there are various opportunities to make this perform
    # better, for example when multiple people subscribe to the same 
    # sev/freq/package
    d = datetime.today() - timedelta(days=3)
    recent = "%s-%0.2d-%0.2d" % (d.year, int(d.month), int(d.day))
    # Connect to the database
    conn = sqlite3.connect(notifydb)
    c = conn.cursor()
    c.execute('SELECT rowid, address, package, severity, reptype FROM subscription WHERE frequency="daily"')
    all_rows = c.fetchall()
    for col in all_rows:
        gen_report(col[1], col[2], col[3], col[4], todaysdate, recent)
    #if today is Wednesday (2), then generate weekly reports
    if datetime.today().weekday() == 2:
        d = datetime.today() - timedelta(days=8)
        lastWeek = "%s-%0.2d-%0.2d" % (d.year, int(d.month), int(d.day))
        c.execute('SELECT rowid, address, package, severity, reptype FROM subscription WHERE frequency="weekly"')
        all_rows = c.fetchall()
        for col in all_rows:
            gen_report(col[1], col[2], col[3], col[4], todaysdate, lastWeek)

    # Close the database
    conn.close()
    return True

def cmd_mail():
    '''Mail out the reports'''
    # Mail header - there are many ways to do this, hardcoding it for now
    mail_header = "CVE Report (xenial)\n"
    # Select the unique email addresses who have opted to receive reports
    # If there is a report available, mail it out
    conn = sqlite3.connect(notifydb)
    c = conn.cursor()
    c.execute('SELECT DISTINCT address FROM subscription')
    all_rows = c.fetchall()
    for col in all_rows:
        todaysfullreport = reportdir + col[0] + '.' + todaysdate
        if not os.path.exists(todaysfullreport):
            if args.debug:
                print("Report [%s] was not generated... Skipping mail step" % todaysfullreport)
            continue
        statinfo = os.stat(todaysfullreport)
        if args.debug:
            print("%s has size %d" % (todaysfullreport, statinfo.st_size))
        if statinfo.st_size == 0:
            if args.debug:
                print("Report [%s] is empty... Skipping mail step" % todaysfullreport)
            continue
        # Generate and send the email
        with open(todaysfullreport) as fp:
            # Create a text/plain message
            msg_text = fp.read()
            msg_body = mail_header + msg_text + mail_footer
            msg = MIMEText(msg_body)
            msg['Subject'] = 'CVE Report for ' + todaysdate
            msg['From'] = 'security@ubuntu.com'
            toaddr = col[0] + ', security@ubuntu.com'
            msg['To'] = toaddr
            # Send the message via our own SMTP server.
            s = smtplib.SMTP('localhost')
            # python3 s.send_message(msg)
            s.sendmail(fromaddr, toaddr, msg.as_string())
            s.quit()
            fp.close()
            if args.debug:
                print("Sent %s" % todaysfullreport)
    # Close the database
    conn.close()
    return True

#
# Main Program
#
parser = argparse.ArgumentParser(description='CVE notification subscription management.')
parser.add_argument('cmd', choices=['help', 'list', 'add', 'del', 'init', 'mail', 'report'])
parser.add_argument("-n", "--number", type=int,
                    help="Identifier of row to delete")
parser.add_argument("-p", "--package",
                  help="Subscribe to the given packages")
parser.add_argument("-e", "--email",
                  help="Subscribe the given email address")
parser.add_argument("-s", "--severity",
                  help="Subscribe at the given severity level")
parser.add_argument("-f", "--frequency",
                  help="Subscribe for reports at the given frequency (daily, weekly)")
parser.add_argument("-t", "--report-type",
                  help="Type of report (full, onchange)")
parser.add_argument("-b", "--notification-db",
                  help="Full path to notification db (defaults to ~/notify/notification.db)")
parser.add_argument("-r", "--report-dir",
                  help="Path to reports (defaults to ~/notify/)")
parser.add_argument("-c", "--script-dir",
                  help="Path to reports (defaults to ~/reviewed/)")
parser.add_argument("-d", "--debug",
                  help="Report debug information", action="store_true")
args = parser.parse_args()
rownum = args.number
cmd = args.cmd
todaysdate = "%s-%0.2d-%0.2d" % (datetime.today().year, int(datetime.today().month), int(datetime.today().day))
if args.notification_db:
    notifydb = args.notification_db
if args.report_dir:
    reportdir = args.report_dir
if args.script_dir:
    scriptdir = args.script_dir

reportdir = os.path.expanduser(reportdir)
scriptdir = os.path.expanduser(scriptdir)
notifydb = os.path.expanduser(notifydb)
uctdir = os.path.expanduser(uctdir)
origdir = os.getcwd()

commands = {
    'init'    : cmd_init,
    'help'    : cmd_help,
    'list'    : cmd_list,
    'add'     : cmd_add,
    'del'     : cmd_del,
    'report'  : cmd_report,
    'mail'    : cmd_mail
}

if cmd in commands:
    commands[cmd]()
else:
    print("Error: Invalid command.\n", file=sys.stderr)
    print_usage()
    sys.exit(1)
