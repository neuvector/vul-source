#!/usr/bin/env python3
#
# Author: Kees Cook <kees@ubuntu.com>
# Author: Marc Deslauriers <marc.deslauriers@ubuntu.com>
# Author: Steve Beattie <sbeattie@ubuntu.com>
# Copyright: 2011-2023 Canonical, Ltd
# License: GPLv3
#
# Walk through the steps to do a standard kernel publication using the
# CVE statuses populated in UCT ahead of time. This handles steps 1
# through 5 of:
# https://wiki.ubuntu.com/SecurityTeam/UpdatePublication
# The reason this script exists is because kernel publication involves
# publishing as many as 30-50 kernels plus the associated meta and
# signed source packages.
#
# This script is still in the extended beta phase...

import argparse
import glob
import os
import shutil
import subprocess
import sys
import tempfile

import cve_lib
import kernel_lib
import usn_lib
from source_map import version_compare

try:
    from itertools import zip_longest
except ImportError:  # XXX python2 fallback
    from itertools import izip_longest as zip_longest

reserved_usn = False
uct_script_dir = os.path.join(os.environ['UCT'], 'scripts')

# adjust this line when adding new kernels
generate_usn_regex = r'^linux-image-(\d|generic|virtual|lowlatency|power|server|omap|raspi|riscv|snapdragon|highbank|allwinner|aws|bluefield|gcp|gke|ibm|intel|nvidia|oem|oracle|azure|joule|kvm|euclid|dell|starfive|xilinx)'

def grouper(iterable, n, fillvalue=None):
    "Collect data into fixed-length chunks or blocks"
    # grouper('ABCDEFG', 3, 'x') --> ABC DEF Gxx"
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def debug(message):
    global args

    if args.debug:
        print(message)


def get_latest_usn_version(release, kernel, database):
    # XXX - replace this with (a) usn_lib.py api call
    cmd = ['./scripts/report-latest-usn-version', '--use-glitchdb', '-r', release, '-D', database, kernel]
    debug('Running "%s" ...' % ' '.join(cmd))
    return subprocess.check_output(cmd, universal_newlines=True).rstrip()


def display_pending_cves(release, kernel, last_usn, version, extra_cves=None):
    # XXX - convert to an api call (report-pending-fixes is python)
    if extra_cves:
        extra_cves_arg = ','.join(extra_cves)
    else:
        extra_cves_arg = ''
    if cve_lib.is_active_esm_release(release):
        release = cve_lib.get_esm_name(release)
    cmd = ['./scripts/report-pending-fixes', '-D', '--states', '-r', release, kernel, last_usn, version, '-a', extra_cves_arg]
    debug('Running "%s" ...' % ' '.join(cmd))
    return subprocess.call(cmd, universal_newlines=True)


def get_pending_cves(release, kernel, last_usn, version):
    # XXX - convert to an api call (report-pending-fixes is python)
    if cve_lib.is_active_esm_release(release):
        release = cve_lib.get_esm_name(release)
    cmd = ['./scripts/report-pending-fixes', '-r', release, kernel, last_usn, version]
    debug('Running "%s" ...' % ' '.join(cmd))
    cves = subprocess.check_output(cmd, universal_newlines=True)
    cves = cves.strip()
    if cves == '':
        return []
    return cves.split('\n')


def get_next_usn(release, kernels):
    cmd = ['ssh', 'people.canonical.com', '~ubuntu-security/bin/get-next-usn', " ".join(kernels.emit_list())]
    debug('Running "%s" ...' % ' '.join(cmd))
    return subprocess.check_output(cmd, universal_newlines=True).rstrip()


def check_upload(usn):
    cmd = ['ssh', 'people.canonical.com', '~ubuntu-security/bin/check-upload', usn]
    debug('Running "%s" ...' % ' '.join(cmd))
    subprocess.check_call(cmd, universal_newlines=True)


class Kernel(object):
    def __init__(self, name, version):
        self.name = name
        self.version = version
        self.meta = None


class KernelReleases(dict):
    # expects a list of (kernel, version) pairs
    # the kernel name can contain a specific release as well
    def __init__(self, kern_list, default_release):
        if default_release:
            self[default_release] = {}
        if kern_list:
            for kernel, version in kern_list:
                if not '/' in kernel:
                    self[default_release][kernel] = Kernel(kernel, version)
                else:
                    release, kernel = kernel.split('/')
                    if release not in self:
                        self[release] = dict()
                    self[release][kernel] = Kernel(kernel, version)

    def emit_list(self):
        "Returns a string representation of all the kernels"

        kernels = list()
        for rel in self.keys():
            for kernel in self[rel]:
                kernels.append(f"{kernel}/{rel}")

        return kernels

class KernelVersionAction(argparse.Action):

    #def __init__(self, option_strings, dest, nargs=None, **kwargs):
    #    if nargs is None:
    #        raise ValueError("nargs required")
    #    super(KernelVersionAction, self).__init__(option_strings, dest, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        #print('%r %r %r' % (namespace, values, option_string))
        if not len(values) % 2 == 0:
            raise ValueError("Must enter kernel and versions in pairs")
        pairs = list(grouper(values, 2))
        # accept and strip trailing colons in the kernel name as the
        # report the prompts to run this script is based on bug report
        # names that are of the form 'linux-VARIANT: VERSION'. We do
        # this to make copy-pasta-ing easier.
        pairs = [(x[:-1], y) if x[-1] == ':' else (x, y) for (x, y) in pairs]
        setattr(namespace, self.dest, pairs)


parser = argparse.ArgumentParser(description='Script to prepare kernel USNS')
parser.add_argument('-i', '--ignore', action='append', help='CVE to ignore (can repeat)')
parser.add_argument('-a', '--add', action='append', help='CVE not in changes to add (can repeat)')
parser.add_argument('-n', '--dry-run', action='store_true', help='Dry Run')
parser.add_argument('-d', '--debug', action='store_true', help='Debugging mode')
parser.add_argument('-D', '--database', action='store', default='database.pickle', help='USN database pickle (default=%(default)s)')

group = parser.add_mutually_exclusive_group(required=False)
group.add_argument('-u', '--usn', action='store', help='Use specific USN')
group.add_argument('-f', '--fetch', action='store_true', help='Fetch a new USN number')

parser.add_argument('-e', '--include-eol', action='store_true', help='Include EoL releases')
parser.add_argument('-E', '--embargoed', action='store_true', help='Publishing an embargoed kernel, skip UCT check for pending CVEs, pull in embargoed descriptions.')
parser.add_argument('-s', '--skip-binary-check', action='store_true', help='Skip binary package build check')
parser.add_argument('-b', '--bypass-usn-check', action='store_true', help='Bypass checks for a USN already existing for the specified kernel')
parser.add_argument('-r', '--regression', action='store_true', help='Treat as a regression')
# pocket should default to "Security" but only if the ppa is ubuntu
parser.add_argument('-p', '--pocket', action='store', default=None, help='Treat USN as a binary pocket copy from RELEASE')
parser.add_argument('-P', '--ppa', action='store', default='ubuntu', help='Use kernels from PPA rather than the Ubuntu archive')
parser.add_argument('-F', '--force', action='store_true', default=False, help='Override sanity checks and continue anyway')
parser.add_argument('--use-changes', action='store', default=None, help='Use previously downloaded changes files from prior run (sets --keep-changes as well')
parser.add_argument('--keep-changes', action='store_true', default=False, help='Keep changes files downloaded by sis-changes')
parser.add_argument("--ignore-released-cves-in-changelog", action='store_true', help="Filter out CVEs already marked as released")
parser.add_argument("--esm-ppa", action='store', help="Add kernels from ESM PPA if any, can be used when merging ESM with active kernels (sets --include-eol)")
parser.add_argument('release', action='store', nargs=1,  help='Primary release name (e.g. xenial)')
parser.add_argument('kernel', action=KernelVersionAction, nargs='+',  help='Kernel source package name and versions; e.g. "linux 4.4.0-42.62. Source package can be a release/name pair"')
args = parser.parse_args()

if not args.dry_run and not args.fetch and args.usn is None:
    print('''No USN specified. Must choose one of the following:
'-n'     dry-run
'-f'     fetch new USN
'-u USN' specific USN''', file=sys.stderr)
    exit(1)

default_release = args.release[0]

if not os.path.exists(args.database):
    print('USN pickle db "%s" not found, please use fetch-db to download it!' % args.database, file=sys.stderr)
    exit(1)

if args.use_changes is not None:
    args.keep_changes = True

cves = set()
if args.add:
    cves.update(args.add)
kernels = KernelReleases(args.kernel, default_release)
meta_kernels = set()

for release in cve_lib.release_sort(kernels.keys()):
    for kernel in sorted(kernels[release]):
        version = kernels[release][kernel].version
        kernels[release][kernel].meta = kernel_lib.meta_kernels.get_meta(release, kernel)
        kernels[release][kernel].signed = kernel_lib.meta_kernels.get_signed(release, kernel)
        debug("%s %s %s" % (kernel, kernels[release][kernel].meta, kernels[release][kernel].signed))

        last_usn_version = get_latest_usn_version(release, kernel, args.database)
        debug("%s %s %s" % (release, kernel, last_usn_version))

        if not args.embargoed:
            rc = display_pending_cves(release, kernel, last_usn_version, version, args.add)
            if not rc == 0 and not args.force:
                print("Incomplete descriptions detected, please fix.")
                exit(1)

            # Don't need to pass additional cves if any here due to them already
            # being added to the cves set()
            pending_cves = set(get_pending_cves(release, kernel, last_usn_version, version))
            if len(pending_cves) > 0:
                cves.update(pending_cves)
            debug("%s %s %s" % (release, kernel, " ".join(cves)))

        if last_usn_version == version and not args.bypass_usn_check:
            print("A USN already exists for %s kernel version %s!" % (kernel, version), file=sys.stderr)
            print("Try using report-mismatched-cve-fixes.py to fix", file=sys.stderr)
            print("... or use --bypass-usn-check if you know what you're doing!", file=sys.stderr)
            exit(1)

if not args.usn:
    if args.dry_run:
        usn = 'N-1'
    elif args.fetch:
        usn = get_next_usn(release, kernels)
        reserved_usn = True
    else:
        raise("Something's gone horribly wrong")
else:
    usn = args.usn

if args.ppa == 'ubuntu' and args.pocket is None:
    args.pocket = "Security"

changes_dir = None
try:
    debug("USN=%s" % usn)

    usn_script = os.path.join(os.environ['HOME'], 'new-usn-%s-%s-%s.sh' % (default_release, "-".join(kernels[default_release]), usn))
    debug("USN script is %s" % usn_script)

    if args.use_changes is not None:
        if not os.path.exists(args.use_changes):
            print("Cached directory for changes files '%s' does not exist!" % (args.use_changes), file=sys.stderr)
            exit(1)
        if not os.path.isdir(args.use_changes):
            print("--use-changes location '%s' is not a directory!" % (args.use_changes), file=sys.stderr)
            exit(1)
        changes_dir = args.use_changes
    else:
        temp_dir = tempfile.mkdtemp(prefix='prepare-kernel-usn-')
        changes_dir = os.path.join(temp_dir, "usn-changes")
        os.mkdir(changes_dir)
        debug('changes dir is %s' % changes_dir)

        for release in kernels:
            intermediate_changes = os.path.join(temp_dir, "usn-%s-%s" % (release, "-".join(kernels[release])[:120]))
            debug('intermediate changes dir is %s' % intermediate_changes)
            # sis-changes command
            cmd = [os.path.join(uct_script_dir, 'sis-changes')]
            if args.include_eol:
                cmd.append('--include-eol')
            if args.skip_binary_check:
                cmd.append('--skip-build-check')
            if args.esm_ppa and cve_lib.is_active_esm_release(release):
                cmd += ['--ppa', args.esm_ppa]
                if not args.include_eol:
                    cmd.append('--include-eol')
            else:
                cmd += ['--ppa', args.ppa]
                if args.pocket:
                    cmd += ['--pocket', args.pocket]
            cmd += ['-r', release, '--download', intermediate_changes]
            for kernel in kernels[release]:
                cmd += [kernel]
                if kernels[release][kernel].meta:
                    cmd += [kernels[release][kernel].meta]
                if kernels[release][kernel].signed:
                    cmd += [kernels[release][kernel].signed]

            try:
                debug("%s" % " ".join(cmd))
            except TypeError as e:
                print('Borked command: %s' % cmd, file=sys.stderr)
            subprocess.check_call(cmd)

            # bleah, need to cope with generated json file
            shutil.move(os.path.join(intermediate_changes, 'binaries.json'),
                        os.path.join(intermediate_changes, '%s-binaries.json' % release))

            for name in os.listdir(intermediate_changes):
                shutil.move(os.path.join(intermediate_changes, name), changes_dir)

    os.chdir(changes_dir)

    # XXX - validate changes files are complete and match expected versions
    # sis-generate-usn command
    cmd = [os.path.join(uct_script_dir, 'sis-generate-usn'), '--kernel-mode', '--no-new-warn']
    if args.ignore:
        cmd += ['--ignore-cves', ','.join(args.ignore)]

    if len(cves) == 0:
        if not args.regression or not args.embargoed:
            print("INFO no cves found, is this a regression or an embargoed update?")
    else:
        cmd += ['--cves', ','.join(cves)]

    if args.ignore_released_cves_in_changelog:
        cmd += ['--ignore-released-cves-in-changelog']

    if args.embargoed:
        cmd += ['--embargoed']

    cmd += ['--filter-bins', generate_usn_regex, usn]
    for release in kernels:
        cmd += ['--binaries-json', '%s-binaries.json' % release]
    cmd += glob.glob('*.changes')

    debug("%s" % " ".join(cmd))
    with open(usn_script, 'w') as f:
        subprocess.check_call(cmd, stdout=f, universal_newlines=True)

    # invoke editor
    if 'EDITOR' in os.environ:
        cmd = [os.environ['EDITOR']]
    else:
        cmd = ['vi']
    cmd.append(usn_script)
    subprocess.check_call(cmd, universal_newlines=True)

    if not args.dry_run:
        subprocess.check_call(['bash', usn_script], universal_newlines=True)
        print("The following check upload run may fail for ESM releases")
        check_upload(usn)

except:
    if reserved_usn:
        print("Please re-use %s! Reserved for %s %s!" % (usn, release, ",".join(kernels)))
    raise
finally:
    if not args.keep_changes and temp_dir and os.path.isdir(temp_dir) \
       and changes_dir and os.path.isdir(changes_dir):
        shutil.rmtree(temp_dir)
    else:
        print('changes files kept in %s' % changes_dir)

debug(args)
print('USN script is %s' % usn_script)
print('SRCPKG="%s"' % " ".join(kernels))
print('USN=%s' % usn)
