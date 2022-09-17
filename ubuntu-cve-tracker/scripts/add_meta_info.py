#!/usr/bin/env python3

import os
import json
import sys

if len(sys.argv) != 4:
    print("Use %s <package> <title> <description>" % sys.argv[0])

package = sys.argv[1]
title = sys.argv[2]
description = sys.argv[3]
json_file = os.environ['UCT'] + "/meta_lists/package-db.json"

with open(json_file, 'r') as handle:
    parsed = json.load(handle)
    parsed.setdefault(package, {})
    parsed[package]['title'] = title
    parsed[package]['description'] = description
    new_content = json.dumps(parsed, indent=4, sort_keys=True)

with open(json_file, 'w') as handle:
    handle.write(new_content)
