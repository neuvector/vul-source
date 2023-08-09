#!/usr/bin/env python3
import sys, os
sys.path.append(os.path.expanduser("~/reviewed/scripts"))
import cve_lib

for rel in cve_lib.releases:
	if rel not in cve_lib.eol_releases and rel != cve_lib.devel_release:
		print(rel)
