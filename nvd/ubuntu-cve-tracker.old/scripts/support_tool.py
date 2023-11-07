#!/usr/bin/env python2
#
# Author: Jamie Strandboge <jamie@ubuntu.com>
# Author: Marc Deslauriers <marc.deslauriers@canonical.com>
# Copyright (C) 2012-2016 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# TODO
# - convert to support database when it is implemented
# - add support length (could pull in Packages files, but probably easier to
#   wait for the support database

from __future__ import print_function
import glob
import json
import optparse
import os
import re
import signal
import subprocess
import sys

devel_release = "zesty"
releases = ['precise', 'trusty', 'xenial', 'yakkety', 'zesty']
flavor_list = ['edubuntu', 'kubuntu', 'lubuntu', 'mythbuntu',
               'ubuntu-mate', 'ubuntu-gnome', 'ubuntustudio', 'xubuntu',
               'ubuntukylin', 'ubuntu-budgie']
seeds_url = 'http://people.canonical.com/~ubuntu-archive/germinate-output'

# TODO: figure out what the following list is for
# These should be based on release manifests
canonical_supported = {
    'precise':  ['ubuntu', 'kubuntu'],
    'trusty':  ['ubuntu'],
    'xenial':  ['ubuntu'],
    'yakkety':  ['ubuntu'],
    'zesty':  ['ubuntu'],
}


def subprocess_setup():
    # Python installs a SIGPIPE handler by default. This is usually not what
    # non-Python subprocesses expect.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def cmd(command, input=None, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, stdin=None, timeout=None):
    '''Try to execute given command (array) and return its stdout, or return
    a textual error if it failed.'''

    try:
        sp = subprocess.Popen(command, stdin=stdin, stdout=stdout, stderr=stderr, close_fds=True, preexec_fn=subprocess_setup)
    except OSError as e:
        return [127, str(e)]

    out, outerr = sp.communicate(input)
    # Handle redirection of stdout
    if out is None:
        out = ''
    # Handle redirection of stderr
    if outerr is None:
        outerr = ''
    return [sp.returncode, out + outerr]


def recursive_rm(dirPath):
    '''recursively remove directory'''
    names = os.listdir(dirPath)
    for name in names:
        path = os.path.join(dirPath, name)
        if not os.path.isdir(path):
            os.unlink(path)
        else:
            recursive_rm(path)
    os.rmdir(dirPath)


def error(out, do_exit=True):
    '''Print error message and exit'''
    try:
        print("ERROR: %s" % (out), file=sys.stderr)
        sys.stderr.flush()
    except IOError:
        pass

    if do_exit:
        sys.exit(1)


def warn(out):
    '''Print warning message'''
    try:
        print("WARN: %s" % (out), file=sys.stderr)
        sys.stderr.flush()
    except IOError:
        pass


def msg(out, output=sys.stdout, newline=True):
    '''Print message'''
    try:
        if newline:
            print("%s" % (out), file=output)
        else:
            print("%s" % (out), file=output, end="")
        output.flush()
    except IOError:
        pass


def download_seeds(directory, update, rels=[], flavors=[]):
    '''Download seed collections'''
    if not update and os.path.isdir(directory):
        msg("INFO: '%s' exists. Using cached entries." % directory, output=sys.stderr)
        return

    if len(rels) == 0 and os.path.exists(directory):
        if not os.path.isdir(directory):
            error("'%s' exists but is not a directory. Aborting" % directory)
        msg("Remove '%s'? " % (directory), newline=False)
        ans = sys.stdin.readline()
        if ans.strip().lower().startswith('y'):
            recursive_rm(directory)
        else:
            msg("Aborting", output=sys.stderr)
            sys.exit(0)

        rels = releases
    rels.sort()

    seeds_dir = re.sub(r'^http://', '', seeds_url)
    pwd = os.getcwd()

    if not os.path.exists(directory):
        os.mkdir(directory)
        os.chdir(directory)
        msg("Downloading seeds directory (may take a while)... ", newline=False)
        rc, report = cmd(['wget', '-r', '-np', '-N', '-l', '1', '-R', '*=*', seeds_url])
        if rc != 0:
            error('wget exited non-zero:\n%s' % report)
        msg("done")

    os.chdir(directory + '/%s' % seeds_dir)
    msg("Downloading seed collections...")
    for r in rels:
        seeds = []
        if len(flavors) > 0:
            for f in flavors:
                seeds += glob.glob('%s.%s' % (f, r))
        else:
            seeds = glob.glob('*.%s' % r)
        seeds.sort()

        topdir = os.getcwd()
        for d in seeds:
            if not os.path.isdir(d):
                continue

            os.chdir(os.path.basename(d))
            fn = os.path.join(d, "all")
            if update and os.path.exists(fn):
                os.unlink(fn)
                msg("INFO: updating '%s'" % fn, output=sys.stderr)

            suburl = seeds_url + "/%s/all" % os.path.basename(d)
            msg("  %s" % suburl)
            rc, report = cmd(['wget', '-N', suburl])
            os.chdir(topdir)
            if rc != 0:
                warn('wget exited non-zero:\n%s' % report)
    msg("Done!")

    os.chdir(pwd)
    msg("Files downloaded to '%s'" % directory)


def _save_db(db, fn):
    '''Save database'''
    # msg("INFO: saving database to '%s'" % fn, output=sys.stderr)
    json.dump(db, open(fn, 'w'), -1, encoding="utf-8")


def _load_db(fn):
    '''Load database'''
    # msg("INFO: reading '%s'" % fn, output=sys.stderr)
    db = json.load(open(fn))
    return db


def read_seeds(topdir):
    '''Read in seeds'''
    seeds_dir = os.path.join(topdir, re.sub(r'^http://', '', seeds_url))

    db['src'] = dict()
    for r in releases:
        db['src'][r] = dict()

    db['bin'] = dict()
    for r in releases:
        db['bin'][r] = dict()

    seeds = sorted(glob.glob("%s/*" % seeds_dir))
    msg("Processing seed collections... ", newline=False)
    for s in seeds:
        if not os.path.isdir(s):
            continue
        tmp = os.path.basename(s).split('.')
        seed = tmp[0]
        release = tmp[1]
        if release not in releases:
            # warn("skipping %s.%s" % (seed, release))
            continue
        # msg("DEBUG: Processing %s.%s" % (seed, release))

        pat = re.compile(r'^(\s|Package)')
        fn = os.path.join(s, 'all')
        if not os.path.exists(fn):
            warn("skipping %s.%s/all (does not exist!)" % (seed, release))
            continue
        f = open(os.path.join(s, 'all'))
        for line in f:
            # print (line)
            if pat.search(line) or line == '':
                continue

            parts = line.split('|')
            if len(parts) < 2:
                continue
            spkg = parts[1].strip()
            if spkg not in db['src'][release]:
                db['src'][release][spkg] = [seed]
            elif seed not in db['src'][release][spkg]:
                db['src'][release][spkg].append(seed)

            bpkg = parts[0].strip()
            if bpkg not in db['bin'][release]:
                db['bin'][release][bpkg] = [seed]
            elif seed not in db['bin'][release][bpkg]:
                db['bin'][release][bpkg].append(seed)

        f.close()
    msg("done")

    return db


def _is_canonical_supported(pkg_type, db, pkg, rel):
    '''Verify if package is canonical_supported'''
    # NOTE: this assumes ppa overlay releases are always supported by Canonical
    if '/' in rel:
        return True
    if rel in releases and rel in db[pkg_type] and pkg in db[pkg_type][rel]:
        for seed in db[pkg_type][rel][pkg]:
            if seed in canonical_supported[rel]:
                return True
    return False


def _is_flavor(pkg_type, db, pkg, rel, flavor):
    '''Verify package is in flavor'''
    if rel in releases and rel in db[pkg_type] and pkg in db[pkg_type][rel]:
        if flavor in db[pkg_type][rel][pkg]:
            return True
    return False


def check_package(pkg_type, db, pkgs, style):
    '''Check support status for package'''
    if style == "text":
        fmt = "%-49s %-12s %-12s %s"
    else:
        fmt = "%s|%s|%s|%s"

    # FIXME: this does not do anything with ppa overlays
    for r in releases:
        all_seeds = []
        canonical_supported_seeds = []
        other_supported_seeds = []
        for p in pkgs:
            found = False
            if p in db[pkg_type][r]:
                for seed in db[pkg_type][r][p]:
                    all_seeds.append(seed)
                    if seed in canonical_supported[r]:
                        canonical_supported_seeds.append(seed)
                        found = True
                    else:
                        other_supported_seeds.append(seed)

            all_seeds.sort()
            canonical_supported_seeds.sort()
            other_supported_seeds.sort()

            status = "unsupported"
            seeds = ""
            if found:
                status = "canonical"
                seeds = ",".join(canonical_supported_seeds)
            elif len(other_supported_seeds) > 0:
                status = "community"
                seeds = ",".join(other_supported_seeds)

            msg(fmt % (p, r, status, seeds))


def dump_packages(db, rels=[], style="machine", flavors=[]):
    '''Dump packages'''
    rels.sort()
    if style == "text":
        fmt = "%-49s %-12s %s"
    else:
        fmt = "%s|%s|%s"

    for r in rels:
        if r not in releases:
            warn("skipping %s" % (r))
            continue

        for t in ['src', 'bin']:
            if t == 'src':
                title = "Sources - %s" % r
            else:
                title = "Binaries - %s" % r
            # Delay output so we don't need to for loops
            out = fmt % (title, "Status", "Seed Collection")

            pkgs = sorted(db[t][r].keys())
            for p in pkgs:
                in_flavor = []
                if len(flavors) > 0:
                    for f in flavors:
                        if _is_flavor(t, db, p, r, f):
                            in_flavor.append(f)
                    if len(in_flavor) == 0:
                        continue
                collection = ""
                status = "unsupported"
                if len(in_flavor) > 0:
                    in_flavor.sort()
                    collection = ",".join(in_flavor)
                    status = "community"
                elif len(db[t][r][p]) > 0:
                    collection = ",".join(db[t][r][p])
                    status = "community"
                if _is_canonical_supported(t, db, p, r):
                    status = "canonical"
                out += fmt % (p, status, collection)
                msg(out)
                out = ""
        msg("")


#
# main
#
if __name__ == "__main__":
    parser = optparse.OptionParser()
    parser.add_option("--seeds-directory", dest="seeds_directory", help="Directory containing seed files", metavar="DIR")
    parser.add_option("--force", help="Update seed files", action='store_true')
    parser.add_option("--download", help="Download seed files", action='store_true')
    parser.add_option("-f", "--json-file", help="JSON file to use", metavar="FILE")
    parser.add_option("-s", "--source", help="Check the support status for source package", metavar="SRCPKG", action='append')
    parser.add_option("-b", "--binary", help="Check the support status for binary package", metavar="BINPKG", action='append')
    parser.add_option("--dump", help="Dump support status", action='store_true')
    parser.add_option("--text", help="Output in text formatting", action='store_true')
    parser.add_option("-r", "--release", help="Specify release with --dump", metavar="REL", action='append')
    parser.add_option("--flavor", help="Specify flavor with --dump", metavar="FLAVOR", action='append')

    (opt, args) = parser.parse_args()
    db = dict()

    flavors = flavor_list
    if opt.flavor:
        flavors = opt.flavor

    rels = releases
    if opt.release:
        rels = opt.release

    style = "machine"
    if opt.text:
        style = "text"

    if opt.download:
        if not opt.seeds_directory:
            error('Must specify --seeds-directory with --download')
        elif not opt.json_file:
            error('Must specify --json-file to write to with --download')
        elif os.path.exists(opt.json_file):
            if not opt.force:
                error("'%s' exists. Aborting (use --force)" % opt.json_file)
            os.unlink(os.path.expanduser(opt.json_file))

        download_seeds(os.path.expanduser(opt.seeds_directory),
                       opt.force, rels, flavors)

        db = read_seeds(os.path.expanduser(opt.seeds_directory))
        _save_db(db, os.path.expanduser(opt.json_file))
        sys.exit(0)
    else:
        if not opt.json_file:
            error('Must specify --json-file to read')
        elif not os.path.exists(os.path.expanduser(opt.json_file)) and \
             not opt.seeds_directory:
            error("'%s' does not exist and --seeds-directory not specified. Aborting")
        elif not os.path.exists(os.path.expanduser(opt.json_file)):
            db = read_seeds(os.path.expanduser(opt.seeds_directory))
            msg("INFO: creating '%s'" % opt.json_file, output=sys.stderr)
            json.dump(db, open(os.path.expanduser(opt.json_file), 'w'),
                      -1, encoding="utf-8")
        else:
            db = _load_db(os.path.expanduser(opt.json_file))

    if opt.source or opt.binary:
        if opt.source:
            check_package('src', db, opt.source, style)
        if opt.binary:
            check_package('bin', db, opt.binary, style)
    elif opt.dump:
        dump_packages(db, rels, style, flavors)
    else:
        error("please specify --dump, --source, --binary, --download")
