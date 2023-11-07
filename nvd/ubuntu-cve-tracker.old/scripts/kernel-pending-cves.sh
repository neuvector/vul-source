#!/bin/sh
# Copyright 2020 Canonical, Ltd
# Author: Steve Beattie <steve.beattie@canonical.com>
# License: GPLv3

# This script is used for reporting and fixing up kernels that were
# addressed in an update before the CVE was assigned for it. The kernel
# triage bot will mark it as pending with a version that predates the
# last USN issued, so either report or fixup the pending CVE statuses.
#
# Sample usage:
# to report all kernels
#   scripts/kernel-pending-cves.sh
# update their status
#   scripts/kernel-pending-cves.sh -u
# check an individual kernel
#   scripts/kernel-pending-cves.sh linux-aws
# update an individual kernel
#   scripts/kernel-pending-cves.sh -u linux-aws
#

set -e

DO_UPDATE=
arg_source=

. "$HOME"/.ubuntu-cve-tracker.conf

if [ -z "$kernel_team_tools_path" ] ; then
    echo "Need to have kernel_team_tools_path defined in ~/.ubuntu-cve-tracker.conf"
    exit 1
fi

if ! [ -d "$kernel_team_tools_path" ] || ! [ -d "$kernel_team_tools_path/.git" ] ; then
    echo "no kteam-tools git repo found"
    echo "do 'git clone git.launchpad.net/~canonical-kernel/+git/kteam-tools'"
    exit 1
fi

KTEAM_TOOLS="$kernel_team_tools_path"

while getopts "uh" opt
do
    case "$opt" in
        u) DO_UPDATE=true;;
        h|*) help ; exit 0;;
    esac
done
shift $(expr $OPTIND - 1)

if [ -n "$1" ] ; then
    arg_source="$1"
fi

eval $(python3 "${KTEAM_TOOLS}/cve-tools/cve-matrix/matrix-config" 'primary')
source_package_list
sources="$RET"

report_pending_fixes_kernel(){
    local kernel="$1"
    local release="$2"
    local version="$3"

    if [ "$release" = "trusty" ] ; then
        release="trusty/esm"
    fi

    if [ "$release" = "xenial" ] ; then
        release="esm-infra/xenial"
    fi

    if [ -z "$DO_UPDATE" ] ; then
        scripts/report-pending-fixes -r "$release" "$kernel" 0 "$version"  -s | grep "$release pending" || true
    else
        scripts/report-pending-fixes -r "$release" "$kernel" 0 "$version"  -s | grep "$release pending" \
        | while read -r line ; do
             CVE=$(echo "$line" | cut -f1 -d' ')
             _kernel=$(echo "$line" | cut -d ' ' -f 2)
             _release=$(echo "$line" | cut -d ' ' -f3)
             _version=$(echo "$line" | cut -d' ' -f5)
             ./scripts/mass-cve-edit -p "$_kernel" -r "$_release" -s released -v "$_version" "$CVE"
        done
    fi
}

# Get list of currently supported ubuntu releases. Given this and the
# later frequent calls to scripts/report-latest-usn-version which
# repeatedly opens the usn db, this script should be converted to python
releases="$(PYTHONPATH=scripts python3 -c \
  'import cve_lib; print(" ".join([ x for x in cve_lib.releases if not x == cve_lib.devel_release and (cve_lib.is_active_release(x) or cve_lib.is_active_esm_release(x)) ]))'
)"

if [ -n "$arg_source" ] ; then
    # TODO: warn if arg_source is not in sources
    sources="$arg_source"
fi

for source in $sources ; do
    for rel in $releases ; do
        last_usn=$("$UCT"/scripts/report-latest-usn-version --use-glitchdb -r "$rel" "$source")
        if [ "$last_usn" != "0~" ] ; then
            echo "$source $rel $last_usn"
            report_pending_fixes_kernel "$source" "$rel" "$last_usn"
        fi
    done
done
