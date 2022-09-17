#!/bin/bash
#
# This will take the USN database defined in ~/.ubuntu-cve-tracker.conf
# ("DB" in the examples below), and create three resulting files:
#   DB.YYYYMMDD: all the USNs in the USN DB as of YYYYMMDD (backup of DB)
#   DB.expired-YYYYMMDD: all the USNs considered expired as of YYYYMMDD
#   DB: all the remaining active USNs
#
# Copyright 2011, Canonical, Ltd.
# Author: Kees Cook <kees@ubuntu.com>
# License: GPLv3
set -e
export LANG=C
now=$(date --utc +%Y%m%d)

. "$HOME"/.ubuntu-cve-tracker.conf

current=$(mktemp -t current-usns-XXXXXX)
"$usn_tool"/usn.py --db "$usn_db_copy" --list | sort > "$current"
echo Current USNs: $(wc -l "$current" | awk '{print $1}')

expiring=$(mktemp -t expiring-usns-XXXXXX)
./scripts/report-expired-usns.py | sort > "$expiring"
count=$(wc -l "$expiring" | awk '{print $1}')
echo Expiring USNs: $count
if [ $count -eq 0 ]; then
    exit 0
fi

staying=$(mktemp -t staying-usns-XXXXXX)
comm -23 "$current" "$expiring" > "$staying"
echo Resulting active USNs: $(wc -l "$staying" | awk '{print $1}')

echo "Exporting expired USNs ..."
expired=$(echo $(sort -n "$expiring") | sed -e 's/ /,/g')
"$usn_tool"/usn.py --db "$usn_db_copy" --export "$expired" > "$usn_db_copy".expired-"$now".yaml

echo "Exporting active USNs ..."
active=$(echo $(sort -n "$staying") | sed -e 's/ /,/g')
"$usn_tool"/usn.py --db "$usn_db_copy" --export "$active" > "$usn_db_copy".active-"$now".yaml

rm -f "$current" "$expiring" "$staying"

mv "$usn_db_copy" "$usn_db_copy"."$now"

echo "Building retirement database ..."
"$usn_tool"/usn.py --db "$usn_db_copy".expired-"$now" --import < "$usn_db_copy".expired-"$now".yaml
echo "Building active database ..."
"$usn_tool"/usn.py --db "$usn_db_copy" --import < "$usn_db_copy".active-"$now".yaml

rm -f "$usn_db_copy".expired-"$now".yaml "$usn_db_copy".active-"$now".yaml

echo Sending to people.canonical.com ...
# These are separate rsyncs to allow accurate final names in the off-chance
# that "$usn_db_copy" isn't actually named "database.pickle" as the last path
# element.
rsync -aPv "$usn_db_copy"."$now" people.canonical.com:~ubuntu-security/usn/database.pickle."$now"
rsync -aPv "$usn_db_copy".expired-"$now" people.canonical.com:~ubuntu-security/usn/database.pickle.expired-"$now"
rsync -aPv "$usn_db_copy" people.canonical.com:~ubuntu-security/usn/database.pickle

echo Done
