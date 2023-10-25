#!/usr/bin/env python3
#
# Author: Eduardo Barretto
# Copyright (C) 2022- Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import datetime
import json
import requests
import os

def query_data(offset):
    url = "https://ubuntu.com/security/notices.json?order=newest&details=LSN"
    if offset:
        url = url + "&offset=" + str(offset)

    response = {}
    try:
        response = requests.get(url).json()
    except:
        print("ERROR: Failed to establish connection, continuing with local db")

    return response

def main():
    db = {}
    filename = "database-lsn.json"
    if os.path.exists(filename):
        with open(filename, 'r') as json_file:
            try:
                db = json.load(json_file)
                print("Reading database-lsn.json")
            except json.decoder.JSONDecodeError:
                print("Creating database-lsn.json")

    total = 20
    offset = 0
    while offset < total:
        data = query_data(offset)
        if not data:
            return 0
        total = data['total_results']
        for notice in data['notices']:
            lsn_id = notice['id']
            if lsn_id in db:
                print('database is up-to-date')
                offset = total
                break
            else:
                print('importing {}'.format(lsn_id))
                db[lsn_id] = {}
                db[lsn_id]['description'] = notice['description']
                db[lsn_id]['releases'] = {}
                for release in notice['release_packages']:
                    db[lsn_id]['releases'][release] = {'sources': {},
                                                       'binaries': {},
                                                       'allbinaries': {}}
                    for item in notice['release_packages'][release]:
                        # lsn json have two entries for same source
                        # one containing the binary as version and
                        # another with the livepatch module version
                        if not item['is_source']:
                            continue
                        db[lsn_id]['releases'][release]['sources'][item['name']] = {
                            'version': item['version'],
                            'description': item['description']
                        }
                        version = item['version'].replace('.', '_')
                        module_name = "lkp_Ubuntu_" + version.split('-')[0] + \
                            r"[_|\d]+_" + item['name'].split('-')[0] + "_(\d+)"
                        db[lsn_id]['releases'][release]['allbinaries'][item['name']] = {
                            "pocket": "livepatch",
                            "module": module_name,
                            "version": lsn_id.split('-')[1].lstrip('0')
                        }
                db[lsn_id]['title'] = notice['title']
                date = datetime.datetime.strptime(notice['published'], "%Y-%m-%dT%H:%M:%S")
                db[lsn_id]['timestamp'] = datetime.datetime.timestamp(date)
                db[lsn_id]['summary'] = notice['title']
                db[lsn_id]['action'] = notice['instructions']
                db[lsn_id]['is_hidden'] = 'False'
                db[lsn_id]['cves'] = notice['cves_ids']
                db[lsn_id]['id'] = notice['id']
                db[lsn_id]['isummary'] = notice['summary']
                db[lsn_id]['related_notices'] = []
                for rn in notice['related_notices']:
                    db[lsn_id]['related_notices'].append(rn['id'])

        offset += 20

    try:
        with open(filename, "w+") as json_file:
            json.dump(db, json_file, indent=4)
    except:
        print(f"Could not write to JSON file: {filename}")

    return 0


if __name__ == '__main__':
    main()
