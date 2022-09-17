'''This module provides an interface to Launchpad Malone.

(C) 2006 Canonical Ltd.
Author: Martin Pitt <martin.pitt@canonical.com>
'''

import xml.sax, xml.sax.handler, re, sys, urllib

class __PlaintextSAXHandler(xml.sax.handler.ContentHandler):
    def __init__(self):
	self.plaintext = ''

    def characters(self, content):
	s = content.encode("UTF-8")
	self.plaintext += content.encode("UTF-8")

def get_distro_releases(distro):
    '''Return a list of supported releases for the given distro.'''

    page = urllib.urlopen('https://launchpad.net/distros/' + distro).read()

    # create plaintext from page
    handler = __PlaintextSAXHandler()
    xml.sax.parseString (page, handler)

    releases = []
    in_details = False
    in_releases = False
    name = None
    status_re = re.compile('^\((\w+)\)$')
    for l in handler.plaintext.splitlines():
	if l.find('distribution details') > 0:
	    in_details = True
	    continue
	if in_details and l.find('Releases:') > 0:
	    in_releases = True
	    continue

	if in_releases:
	    l = l.strip()

	    if not l:
		continue

	    if l.find(' ') > 0:
		break # next section header

	    if status_re.match(l):
		assert name
		if l != '(OBSOLETE)':
		    releases.append(name)
		name = None
		continue

	    if not name:
		name = l

    return releases
	
def get_distrorelease_cve_report(distro, release):
    '''Parse the given distribution release's CVE report and return a mapping

      bug number -> ([list of CVEs], package -> status)

      E. g. result[1234] == (['CVE-2006-1234', 'CVE-2006-2345'], 
         {'firefox': 'Fix released', 'mozilla': 'Unconfirmed'})
    '''

    r = urllib.urlopen('https://launchpad.net/distros/%s/%s/+cve' % 
	(distro, release)).read()

    # create plaintext from report
    handler = __PlaintextSAXHandler()
    xml.sax.parseString (r, handler)

    # parse plaintext and generate map
    map = {}
    currbug = None
    currpkg = None
    bug_re = re.compile('^bug\s*#(\d+):', re.I)
    cve_re = re.compile('^(CVE-\d+-\d+)$')
    pkg_re = re.compile('^([\w._+-]+)(?:\s*\([\w ]+\))$', re.I)
    status_re = re.compile('^([\w ]+)(?:, assigned to|\(unassigned| by)', re.I)
    for l in handler.plaintext.splitlines():
	l = l.strip()
	if not l:
	    continue

	# bug line
	m = bug_re.match(l)
	if m:
	    currbug = int(m.group(1))
	    #print 'bug line', l, '->', currbug
	    continue

	# CVE line
	m = cve_re.match(l)
	if m:
	    assert currbug
	    map.setdefault(currbug, ([], {}))[0].append(m.group(1))
	    #print 'CVE line', l, '->', map[currbug]
	    continue

	# status line
	m = status_re.match(l)
	if m:
	    if not currpkg:
		print >> sys.stderr, 'ERROR: bug', currbug, 'has no associated package'
		continue

	    map.setdefault(currbug, ([], {}))[1][currpkg] = m.group(1)
	    #print 'status line', l, '->', map[currbug]
	    currpkg = None
	    continue

	# package line
	m = pkg_re.match(l)
	if m and currbug:
	    currpkg = m.group(1)
	    #print 'package line:', l, '->', currpkg
	    continue

	# if currbug:
	#    print 'Unknown line:', l

    return map

def get_cve_report(distro):
    '''Generate CVE report for all releases of given distro and return mapping

      CVE -> package -> release -> (bug#, status)

      E. g. result['CVE-2006-1234']['firefox']['dapper'] == (123, 'Fix released')
    '''

    map = {}

    releases = get_distro_releases(distro)
    # first release is the current development release which does not have
    # backport tags or a release specific CVE report; use the floating distro
    # task.
    releases[0] = ''
    for rel in releases:
	rel_map = get_distrorelease_cve_report(distro, rel)

	for bug, (cves, pkgstats) in rel_map.iteritems():
	    for cve in cves:
		for pkg, pkgstat in pkgstats.iteritems():
		    map.setdefault(cve, {}).setdefault(pkg, {})[rel] = \
			(bug, pkgstat)

    return map

for k, v in get_cve_report('ubuntu').iteritems():
    print k, ':', v
