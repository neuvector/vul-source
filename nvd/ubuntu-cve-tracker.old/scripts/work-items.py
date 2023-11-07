#!/usr/bin/env python2
#
# Author: Jamie Strandboge <jamie@ubuntu.com>
# Copyright (C) 2011-2012 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Usage:
# $ export RELEASE=precise
# $ export TEAM=canonical-security
# $ wget -qN http://status.ubuntu.com/ubuntu-$RELEASE/$TEAM.json
# $ work-items.py -r $RELEASE -t $TEAM -f ./$TEAM.json --html > out.html
# $ work-items.py -r $RELEASE -t $TEAM -f ./$TEAM.json > out.txt
#

from __future__ import print_function
import json
import optparse
import os
import re
import sys

# <num weeks> * <40 hours per week> / 8 hours a day
days_in_cycle = 25 * 40 / 8


def _debug(s):
    '''Print debug message'''
    if (opt.debug):
        print('DEBUG: %s' % (s), file=sys.stderr)


def _warn(s):
    '''Print warning'''
    print('WARN: %s' % (s), file=sys.stderr)


def _error(s, exit_with_error=True):
    '''Print error'''
    print('ERROR: %s' % (s), file=sys.stderr)
    if exit_with_error:
        sys.exit(1)


def _get_css():
    '''CSS for reports'''
    css = '''
<style type="text/css">
h1, h2, h3, h4, h5 {
 color: #3b2e1e;
}
table {
 border-collapse: collapse;
 border: 2px solid #3b2e1e;
}
th {
 border-bottom: 2px solid #3b2e1e;
 color: #3b2e1e;
 font-size: smaller;
}
/* basic styling */
td {
 border: 1px solid #3b2e1e;
 text-align: center;
 padding-top: 0.1em;
 padding-bottom: 0.1em;
 padding-left: 0.5em;
 padding-right: 0.5em;
 background-color: white;
 font-size: smaller;
}
td.override {
 text-align: left;
}
</style>
'''
    return css


def _num_to_str(n):
    '''Print an integer if ends with '.0', otherwise float'''
    s = ""
    if re.search(r'\.0', "%f" % n):
        s = "%d" % int(n)
    else:
        s = "%.1f" % (float(n))
    return s


def _wi_format_ind_row(name, wi, html):
    '''Format row'''
    ret = ""
    if html:
        ret += " <tr>\n"
        ret += "  <td class='override'>%s</td>\n" % name
    else:
        ret += "%-12s" % (name)

    wi_total = 0
    wi_comp_total = 0
    wi_imp_total = 0
    wi_imp_comp_total = 0
    wi_teamtotal = dict()
    wi_comp_teamtotal = dict()
    time_imp_total = 0
    time_imp_comp_total = 0
    time_total = 0
    time_comp_total = 0
    time_imp_teamtotal = 0
    time_teamtotal = 0
    for p in workitem_priorities:
        if p not in wi_teamtotal:
            wi_teamtotal[p] = 0
        if p not in wi_comp_teamtotal:
            wi_comp_teamtotal[p] = 0

        wi_teamtotal[p] += wi[p]['total']
        wi_comp_teamtotal[p] += wi[p]['completed']

        if p in workitem_imp_priorities:
            time_imp_teamtotal += wi[p]['est_days']
            time_imp_total += wi[p]['est_days']
            time_imp_comp_total += wi[p]['completed_days']
            wi_imp_total += wi[p]['total']
            wi_imp_comp_total += wi[p]['completed']

        percent = ""
        if wi[p]['total'] > 0:
            percent = " (%s%%)" % (_num_to_str(float(wi[p]['completed']) / float(wi[p]['total']) * 100))

        days = ""
        if wi[p]['total'] < 0.01:
            t = "-"
        else:
            t = "%s/%s" % (_num_to_str(wi[p]['completed']), _num_to_str(wi[p]['total']))
            days = ", (%s/%sd)" % (_num_to_str(wi[p]['completed_days']), _num_to_str(wi[p]['est_days']))

        cell = "%s%s%s" % (t, percent, days)
        if html:
            ret += "  <td>%s</td>\n" % cell
        else:
            ret += workitem_txt_col_fmt % (cell)

        wi_total += wi[p]['total']
        wi_comp_total += wi[p]['completed']
        time_total += wi[p]['est_days']
        time_comp_total += wi[p]['completed_days']

    # total
    percent = 0
    if wi_total > 0:
        percent = _num_to_str(float(wi_comp_total) / float(wi_total) * 100)
    cell = "%d (%s%%), (%s/%sd)" % (wi_total, percent, _num_to_str(time_comp_total), _num_to_str(time_total))
    if html:
        ret += "  <td>%s</td>\n" % (cell)
    else:
        ret += workitem_txt_col_fmt % (cell)

    # important total
    cell = "-"
    if wi_imp_total > 0:
        percent = float(wi_imp_comp_total) / float(wi_imp_total) * 100
        cell = "%d/%d (%s%%), (%s/%sd)" % (wi_imp_comp_total, wi_imp_total, _num_to_str(percent), _num_to_str(time_imp_comp_total), _num_to_str(time_imp_total))
    if html:
        ret += "  <td>%s</td>\n" % (cell)
    else:
        ret += workitem_txt_col_fmt % (cell)

    # dev percentage
    imp_percent = float(time_imp_total) / float(days_in_cycle) * 100
    percent = float(time_total) / float(days_in_cycle) * 100
    cell = "%s%%, %s%%" % (_num_to_str(imp_percent), _num_to_str(percent))
    if html:
        ret += "  <td>%s</tr>\n" % (cell)
    else:
        ret += "%s" % (cell)

    if html:
        ret += " </tr>"
    ret += "\n"

    time_teamtotal += time_total

    return ret, wi_teamtotal, wi_comp_teamtotal, time_teamtotal, time_imp_teamtotal


def _wi_print(wi, release, html, html_minimal, team):
    '''Print work items'''

    wi_teamtotal = dict()
    wi_comp_teamtotal = dict()
    time_teamtotal = 0
    time_imp_teamtotal = 0
    summary_teamtotal = 0
    teammembers = []

    for p in workitem_priorities:
        wi_teamtotal[p] = 0
        wi_comp_teamtotal[p] = 0

    out = ""
    if html:
        out = "<html>\n"
        out += "<head>%s</head>" % (_get_css())
        out += "<body>\n"
        if not html_minimal:
            out += '''
<h1>Work Items Breakdown (%s)</h1>
<h2>Individuals</h2>
<p>
Work items for team members are broken down by priority with a percentage
completed based on work items that are marked 'Done' vs everything else (TODO:
postponed). If time estimates are available, they are expressed as a ratio of
completed days to total estimated days (completed days is simply the sum of all
estimated days for completed items) with an additional column showing the
development load on the team member (percentage of time used for development
work (split between important work items and total work items).
</p>
''' % (release.capitalize())
        out += "<table>\n"
    else:
        out += "Work Items Breakdown (%s)\n\n" % (release.capitalize())

    header = ['Name'] + workitem_priorities + ['Total', 'Total (%s)' % ", ".join(workitem_imp_priorities), 'Dev workload (imp, all)']
    for h in header:
        if html:
            out += " <th>%s</th>\n" % (h.capitalize())
        else:
            if h == "Name":
                out += "%-12s" % (h)
            else:
                out += workitem_txt_col_fmt % (h.capitalize())
    if not html:
        out += "\n"

    for name, entries in work_items.iteritems():
        # TODO: break this into two functions-- one to generate a list of
        # columns and second to format those columns
        tmp_out, tmp_teamtotal, tmp_comp_teamtotal, tmp_time_teamtotal, tmp_time_imp_teamtotal = _wi_format_ind_row(name, entries, html=html)
        out += tmp_out
        for p, v in tmp_teamtotal.iteritems():
            wi_teamtotal[p] += v
        for p, v in tmp_comp_teamtotal.iteritems():
            wi_comp_teamtotal[p] += v
        time_teamtotal += tmp_time_teamtotal
        time_imp_teamtotal += tmp_time_imp_teamtotal

        if name not in teammembers:
            teammembers.append(name)

    if not html_minimal:
        if html:
            out += "</table>"
            out += "<h2>Team</h2>\n"
            out += '''<table>'''
        else:
            out += "\n\nTeam\n\n"

        for p in workitem_priorities:
            percent = ""
            if wi_teamtotal[p] > 0:
                percent = " (%s%%)" % (_num_to_str(float(wi_comp_teamtotal[p]) / float(wi_teamtotal[p]) * 100))
            if html:
                out += " <tr><td class='override'>%s</td>" % (p.capitalize())
            else:
                out += workitem_txt_col_fmt % (p.capitalize())

            cell = "%d/%d%s" % (wi_comp_teamtotal[p], wi_teamtotal[p], percent)
            if html:
                out += "<td>%s</td></tr>" % (cell)
            else:
                out += cell
            out += "\n"
        if html:
            out += "</table>\n<p>"

        summary_teamtotal = days_in_cycle * len(teammembers)

        out += "\nTeam time: %d days\n" % (time_teamtotal)
        if html:
            out += "</br>"
        out += "Team time (%s): %d days\n" % (", ".join(workitem_imp_priorities), time_imp_teamtotal)
        if html:
            out += "</br>"
        out += "Team time (available): %d days (assigned %0.1f%% to %s and %0.1f%% to all development work)\n" % (summary_teamtotal, time_imp_teamtotal / summary_teamtotal * 100, "/".join(workitem_imp_priorities), time_teamtotal / summary_teamtotal * 100)

        if team == "canonical-security":
            if html:
                out += "</br>"
            recommended = dict()
            recommended['dev'] = .25 * days_in_cycle
            recommended['reactive'] = .6 * days_in_cycle
            recommended['other'] = .15 * days_in_cycle
            out += "Recommended member workload (in days):"
            r_keys = sorted(recommended.keys())
            for r in r_keys:
                out += " %d %s," % (recommended[r], r)
            out = out.rstrip(",")

        if html:
            out += "</p>\n</body></html>\n"

    return out


def _load_db(db, team):
    '''Read json data into work_items dictionary. Format is as follows:
         wi[member][priority][counts]
       where 'member' is the nick of the team member, 'priority' is one of
       workitem_priorities and 'counts' is one of workitem_priority_counts.
    '''
    def _validate_work_items(wi):
        '''Make sure we have a valid work items dictionary'''
        rc = False
        err = ""
        for m, priorities in wi.iteritems():
            for p in priorities:
                if p not in workitem_priorities:
                    _warn("'%s' is not a valid priority in: %s" % (p, wi[m]))
                    return rc
                for c in wi[m][p].keys():
                    if c not in workitem_priority_counts:
                        _warn("'%s' is not a valid count field for '%s': %s" % (c, p, wi[m][p]))
                        return rc
                    try:
                        float(wi[m][p][c])
                    except Exception:
                        _warn("'%s' is not a valid count for '%s': %s" % (str(c), p, wi[m][p][c]))
                        return rc
        rc = True
        return (rc, err)

    # Some input validation
    if team not in db['teams']:
        _error("Could not find team '%s' in database" % (team))

    members = db['teams'][team]
    _debug("(_load_db) Members of %s: %s" % (team, members))

    specs = db['specs'].keys()
    _debug("(_load_db) Specifications for team '%s': %s" % (team, specs))

    # Fill in work items for each member
    wi = dict()
    for m in members:
        # Skip members with no work items
        if m not in db['workitems_by_assignee']:
            # _warn("could not find '%s' in workitems_by_assignee" % (m))
            continue

        # initialize the member dictionary
        wi[m] = dict()
        for p in workitem_priorities:
            wi[m][p] = dict([(key, 0) for key in workitem_priority_counts])

        # populate the member dictionary
        for status, items in db['workitems_by_assignee'][m].iteritems():
            if status not in ['blocked', 'done', 'inprogress', 'postponed', 'todo']:
                if status != "complexity":
                    _debug("(_load_db) Skipping '%s' (%s)" % (status, items))
                continue

            for spec, desc, prio, url in items:
                prio = prio.lower()

                # Clean up desc so we can have:
                #  ... (medium) (1.0)
                #  ... (medium)(1.0)
                #  ...(medium)(1.0)
                desc_clean = re.sub('([^ ])\(', '\\1 (', desc)

                # parse the description for security team formatting of time estimates
                for tok in desc_clean.split():
                    if re.search(r'^\((%s)\)$' % "|".join(workitem_priorities), tok):
                        prio_override = tok.strip("()")
                        if prio != prio_override:
                            _debug("(_load_db) Overriding priority '%s' to '%s': %s" % (prio, prio_override, desc))
                            prio = prio_override

                if prio not in workitem_priorities:
                    _warn("Skipping unknown priority '%s' for '%s: %s'" % (prio, spec, desc))
                    continue

                wi[m][prio]['total'] += 1
                # TODO: how to handle postponed
                if status == 'done':
                    wi[m][prio]['completed'] += 1

                # parse the description for security team formatting of time estimates
                for tok in desc_clean.split():
                    if re.search(r'^\([0-9]+(\.[0-9]+){0,1}\)$', tok):
                        d = float(tok.strip("()"))
                        wi[m][prio]['est_days'] += d
                        if status == 'done':
                            wi[m][prio]['completed_days'] += d

        _debug("(_load_db) %s: %s" % (m, wi[m]))

    if not _validate_work_items(wi):
        _error("Work items does not validate")

    return wi


#
# main
#
if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("-f", "--data-file", dest="data_file", help="json data file", metavar="FILE")
    parser.add_option("-r", "--release", dest="release", help="Ubuntu release", metavar="REL")
    parser.add_option("-t", "--team", dest="team", help="Team to report on", metavar="TEAM", default="canonical-security")
    parser.add_option("--html", help="Format as html", action='store_true', default=False)
    parser.add_option("--html-minimal", help="Format as minimal html", action='store_true', default=False)
    parser.add_option("-d", "--debug", help="Show debugging output", action='store_true', default=False)
    (opt, args) = parser.parse_args()

    work_items = dict()
    workitem_priorities = ['essential', 'high', 'medium', 'low', 'undefined']
    workitem_imp_priorities = ['essential', 'high']
    workitem_priority_counts = ['completed', 'total', 'est_days', 'completed_days']
    workitem_txt_col_fmt = "%-26s"

    if not opt.data_file or not os.path.exists(opt.data_file):
        _error('Must specify a valid path to the data file')

    if not opt.release:
        _error('Must specify an Ubuntu release')

    # Read in stats
    db = json.loads(open(opt.data_file).read())
    work_items = _load_db(db, team=opt.team)

    print(_wi_print(work_items, opt.release, opt.html, opt.html_minimal, opt.team))
