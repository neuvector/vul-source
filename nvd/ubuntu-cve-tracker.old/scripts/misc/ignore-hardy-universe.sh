#!/bin/sh

#
# Sample script to help with mass triage.
# This will look at open hardy CVEs that are:
# - needed or needs-triage
# - low priority (by) default
#
# Then use mass-cve-edit to mark them 'ignored (end of life)'
#
# It would be nice if this was less of a hack and checked Assigned, so it
# could be used without worry.
#
# Usage:
# ./ignore-hardy-universe.sh <file> <prio>
#
# <file> is expected to be in the format of:
# CVE-2006-2219	phpbb2
# CVE-2006-2220	phpbb2
# CVE-2007-0255	xine-ui
# CVE-2007-0667	sql-ledger
#
# This can be obtained by going to:
# http://people.canonical.com/~ubuntu-security/cve/universe.html
#
# Then holding Ctrl, click and highlight the CVE and Package fields and pasting
# them into a file.
#

set -e

infile="$1"
if [ ! -s "$infile" ]; then
    echo "'$infile' does not exist" >&2
    exit 1
fi
shift

prio="low"
if [ -n "$1" ]; then
    prio="$1"
fi

cd $UCT
cat "$infile" | while read cve pkg ; do
    f="./active/$cve"

    if [ ! -s "$f" ]; then
        echo "Skipping '$f' (file does not exist)" >&2
        continue
    fi

    p=`echo $pkg | sed 's#+#.#g'`
    hardy_status=`egrep "^hardy_${p}:" $f | awk '{print $2}'`
    priority=`egrep '^Priority:' $f | awk '{print $2}'`
    hardy_priority=`egrep "^Priority_hardy_${p}:" $f | awk '{print $2}'`
    pkg_priority=`egrep "^Priority_${p}:" $f | awk '{print $2}'`

    if ! echo "$hardy_status" | egrep -q "need" ; then
        echo "Skipping $cve/$pkg (status is $hardy_status)" >&2
        continue
    fi
    if [ -n "$hardy_priority" ] && [ "$hardy_priority" != "$prio" ]; then
        echo "Skipping $cve/$pkg (priority is $hardy_priority)" >&2
        continue
    elif [ -n "$pkg_priority" ] && [ "$pkg_priority" != "$prio" ]; then
        echo "Skipping $cve/$pkg (priority is $pkg_priority)" >&2
        continue
    elif [ -n "$priority" ] && [ "$priority" != "$prio" ]; then
        echo "Skipping $cve/$pkg (priority is $priority)" >&2
        continue
    fi
    #if echo "$cve" | egrep -q "CVE-2011" ; then
    #    echo "Skipping $cve/$pkg (CVE is from 2011)" >&2
    #    continue
    #fi

    #echo "CVE: $cve, PKG: $pkg, status: $hardy_status, priority=$priority, hardy_priority=$hardy_priority, pkg_priority=$pkg_priority"
    ./scripts/mass-cve-edit -r hardy -p $pkg -s 'ignored (end of life)' $cve
done
