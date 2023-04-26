#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: Kees Cook <kees@ubuntu.com>
# Author: Jamie Strandboge <jamie@ubuntu.com>
# Author: Steve Beattie <sbeattie@ubuntu.com>
# Copyright (C) 2005-2017 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Helper functions and data structures for dealing with the kernel
# packages, which are very very special.
from __future__ import print_function

import sys

# XXX kernel_srcs probably belongs here, too
from cve_lib import (kernel_srcs, get_esm_name, is_active_esm_release)


# converts a kernel source package name to the signed version, based off
# of the default naming style linux-FOO -> linux-signed-FOO
def convert_name_to_signed(kernel):
    if not kernel.startswith('linux'):
        raise ValueError("received non-kernel source name: %s" % kernel)
    return 'linux-signed' + kernel[5:]

# converts a kernel source package name to the meta version, based off
# of the default naming style linux-FOO -> linux-meta-FOO
def convert_name_to_meta(kernel):
    if not kernel.startswith('linux'):
        raise ValueError("received non-kernel source name: %s" % kernel)
    return 'linux-meta' + kernel[5:]

class MetaKernelTable(object):

    def __init__(self):
        self.table = dict()

    # sources is expected to a be a list, the primary kernel first
    # e.g. add_new_kernel('precise', ['linux', 'lbm-3.2'], '-3.2.0')
    def add_new_kernel(self, release, sources, suffix, signed='DEFAULT', ignore_usn=False, ignore_mabi=False, ppa=None):
        if release not in self.table:
            self.table[release] = dict()
        (primary, subordinates) = (sources[0], sources[1:])
        self.table[release][primary] = dict()
        self.table[release][primary]['suffix'] = suffix
        self.table[release][primary]['meta'] = convert_name_to_meta(primary)
        self.table[release][primary]['subordinates'] = subordinates
        if signed == 'DEFAULT':
            self.table[release][primary]['signed'] = convert_name_to_signed(primary)
        else:
            self.table[release][primary]['signed'] = signed
        self.table[release][primary]['ignore_usn'] = ignore_usn
        self.table[release][primary]['ignore_mabi'] = ignore_mabi
        # None here equals the ubuntu archive
        self.table[release][primary]['ppa'] = ppa

    # wrapper function for edge kernels
    # XXX the better way to identify if a kernel is an edge kernel is to
    # determine if the meta source package provides a regular meta
    # package or an edge meta package, which will require a launchpad
    # lookup (sigh).
    def add_new_edge_kernel(self, release, sources, suffix, signed='DEFAULT'):
        self.add_new_kernel(release, sources, suffix, signed, ignore_usn=True, ignore_mabi=True)

    def consistency_check(self):
        kernels = set()
        if sys.version_info[0] == 3:
            for release in iter(self.table.values()):
                kernels.update(release.keys())
        else:
            for release in self.table.itervalues():
                kernels.update(release.keys())

        if not kernels.issubset(kernel_srcs):
            print('WARNING: MetaKernelTable contains the following kernels not in kernel_sources: ' +
                  '%s' % ' '.join(kernels.difference(kernel_srcs)))

    def _get_attribute(self, attribute, release, kernel):
        if release in self.table and kernel in self.table[release]:
            return self.table[release][kernel][attribute]
        # we try a fallback here for esm kernels, to ensure that either
        # looking up trusty/esm or trusty will get the right attribute.
        # XXX This could be a problem if we have some kernels in a ppa
        # and some not for a given release.
        elif is_active_esm_release(release):
            esm_release = get_esm_name(release)
            if esm_release in self.table and kernel in self.table[esm_release]:
                return self.table[esm_release][kernel][attribute]
        return None

    def get_meta(self, release, kernel, quiet=False):
        meta = self._get_attribute('meta', release, kernel)
        if not meta and not quiet:
            print("Unable to find meta kernel for kernel %s/%s" % (kernel, release), file=sys.stderr)
        return meta

    def get_signed(self, release, kernel, quiet=False):
        signed = self._get_attribute('signed', release, kernel)
        if not signed and not quiet:
            print("Unable to find signed kernel for kernel %s/%s" % (kernel, release), file=sys.stderr)
        return signed

    def get_ppa(self, kernel, release, quiet=True):
        ppa = self._get_attribute('ppa', release, kernel)
        if not ppa and not quiet:
            print("Unable to find ppa for kernel %s/%s" % (kernel, release), file=sys.stderr)
        return ppa

    def get_next_kernel(self):
        for release in self.table:
            for kernel in self.table[release]:
                srcs = [kernel]
                if len(self.table[release][kernel]['subordinates']) > 0:
                    srcs.extend(self.table[release][kernel]['subordinates'])
                meta = self.table[release][kernel]['meta']
                signed = self.table[release][kernel]['signed']
                yield (release, srcs, meta, signed)

    def ignore_usn(self, release, kernel):
        return self.table[release][kernel]['ignore_usn']

    def ignore_mabi(self, release, kernel):
        return self.table[release][kernel]['ignore_mabi']


meta_kernels = MetaKernelTable()
meta_kernels.add_new_kernel('trusty/esm', ['linux'], '-3.13.0', ppa='ubuntu-esm/esm-infra-security')
meta_kernels.add_new_kernel('trusty/esm', ['linux-lts-xenial'], '-4.4.0', ppa='ubuntu-esm/esm-infra-security')
meta_kernels.add_new_kernel('trusty/esm', ['linux-azure'], '-4.15.0', ppa='ubuntu-esm/esm-infra-security')
meta_kernels.add_new_kernel('trusty/esm', ['linux-aws'], '-4.4.0', signed=False, ppa='ubuntu-esm/esm-infra-security')
meta_kernels.add_new_kernel('xenial', ['linux'], '-4.4.0')
meta_kernels.add_new_kernel('xenial', ['linux-raspi2'], '-4.4.0', signed=False)
meta_kernels.add_new_kernel('xenial', ['linux-aws'], '-4.4.0', signed=False)
meta_kernels.add_new_kernel('xenial', ['linux-aws-hwe'], '-4.15.0')
meta_kernels.add_new_kernel('xenial', ['linux-azure'], '-4.11.0')   # suffix may need to change, but it looks like it is ignored
#meta_kernels.add_new_edge_kernel('xenial', ['linux-azure-edge'], '-4.11.0')   # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('xenial', ['linux-gcp'], '-4.8.0')  # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('xenial', ['linux-gke'], '-4.4.0', signed=False)
meta_kernels.add_new_kernel('xenial', ['linux-kvm'], '-4.4.0', signed=False)
meta_kernels.add_new_kernel('xenial', ['linux-oem'], '-4.13.0')
meta_kernels.add_new_kernel('xenial', ['linux-oracle'], '-4.15.0')
meta_kernels.add_new_kernel('xenial', ['linux-snapdragon'], '-4.4.0', signed=False)
meta_kernels.add_new_kernel('xenial', ['linux-hwe'], '-4.8.0')
meta_kernels.add_new_edge_kernel('xenial', ['linux-hwe-edge'], '-4.8.0')
meta_kernels.add_new_kernel('esm-infra/xenial', ['linux'], '-4.4.0', ppa='ubuntu-esm/esm-infra-security')
meta_kernels.add_new_kernel('esm-infra/xenial', ['linux-aws'], '-4.4.0', signed=False, ppa='ubuntu-esm/esm-infra-security')
meta_kernels.add_new_kernel('esm-infra/xenial', ['linux-aws-hwe'], '-4.15.0', ppa='ubuntu-esm/esm-infra-security')
meta_kernels.add_new_kernel('esm-infra/xenial', ['linux-azure'], '-4.15.0', ppa='ubuntu-esm/esm-infra-security')
meta_kernels.add_new_kernel('esm-infra/xenial', ['linux-gcp'], '-4.15.0', ppa='ubuntu-esm/esm-infra-security')
meta_kernels.add_new_kernel('esm-infra/xenial', ['linux-hwe'], '-4.15.0', ppa='ubuntu-esm/esm-infra-security')
meta_kernels.add_new_kernel('esm-infra/xenial', ['linux-kvm'], '-4.4.0', signed=False, ppa='ubuntu-esm/esm-infra-security')
meta_kernels.add_new_kernel('esm-infra/xenial', ['linux-oracle'], '-4.15.0', ppa='ubuntu-esm/esm-infra-security')
meta_kernels.add_new_kernel('bionic', ['linux'], '-4.15.0')
meta_kernels.add_new_kernel('bionic', ['linux-raspi2'], '-4.15.0', signed=False)
meta_kernels.add_new_kernel('bionic', ['linux-raspi2-5.3'], '-5.3.0', signed=False)
meta_kernels.add_new_kernel('bionic', ['linux-raspi-5.4'], '-5.4.0', signed=False)
meta_kernels.add_new_kernel('bionic', ['linux-snapdragon'], '-4.15.0', signed=False)
meta_kernels.add_new_kernel('bionic', ['linux-oem'], '-4.15.0')
meta_kernels.add_new_kernel('bionic', ['linux-oem-osp1'], '-5.0.0')
meta_kernels.add_new_kernel('bionic', ['linux-aws'], '-4.15.0')
meta_kernels.add_new_kernel('bionic', ['linux-aws-5.0'], '-5.0.0', signed=False)
meta_kernels.add_new_kernel('bionic', ['linux-aws-5.3'], '-5.3.0', signed=False)
meta_kernels.add_new_kernel('bionic', ['linux-aws-5.4'], '-5.4.0')
meta_kernels.add_new_edge_kernel('bionic', ['linux-aws-edge'], '-4.18.0', signed=False)
meta_kernels.add_new_kernel('bionic', ['linux-azure'], '-4.15.0')   # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('bionic', ['linux-azure-4.15'], '-4.15.0')
meta_kernels.add_new_kernel('bionic', ['linux-azure-5.3'], '-5.3.0')
meta_kernels.add_new_kernel('bionic', ['linux-azure-5.4'], '-5.4.0')
meta_kernels.add_new_edge_kernel('bionic', ['linux-azure-edge'], '-4.18.0')   # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('bionic', ['linux-gcp'], '-4.15.0')  # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_edge_kernel('bionic', ['linux-gcp-edge'], '-4.15.0')  # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('bionic', ['linux-dell300x'], '-4.15.0')
meta_kernels.add_new_kernel('bionic', ['linux-gcp-4.15'], '-4.15.0')  # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('bionic', ['linux-gcp-5.3'], '-5.3.0')
meta_kernels.add_new_kernel('bionic', ['linux-gcp-5.4'], '-5.4.0')
meta_kernels.add_new_kernel('bionic', ['linux-gke-4.15'], '-4.15.0')
meta_kernels.add_new_kernel('bionic', ['linux-gke-5.0'], '-5.0')
meta_kernels.add_new_kernel('bionic', ['linux-gke-5.3'], '-5.3')
meta_kernels.add_new_kernel('bionic', ['linux-gke-5.4'], '-5.4.0')
meta_kernels.add_new_kernel('bionic', ['linux-gkeop-5.4'], '-5.4.0')
meta_kernels.add_new_kernel('bionic', ['linux-kvm'], '-4.15.0', signed=False)
meta_kernels.add_new_kernel('bionic', ['linux-oracle'], '-4.15.0')
meta_kernels.add_new_kernel('bionic', ['linux-oracle-5.0'], '-5.0.0')
meta_kernels.add_new_kernel('bionic', ['linux-oracle-5.3'], '-5.3.0')
meta_kernels.add_new_kernel('bionic', ['linux-oracle-5.4'], '-5.4.0')
meta_kernels.add_new_kernel('bionic', ['linux-hwe'], '-4.18.0')
meta_kernels.add_new_kernel('bionic', ['linux-hwe-5.4'], '-5.4.0')
meta_kernels.add_new_edge_kernel('bionic', ['linux-hwe-edge'], '-4.18.0')
meta_kernels.add_new_kernel('bionic', ['linux-ibm-5.4'], '-5.4.0')
meta_kernels.add_new_kernel('focal', ['linux'], '-5.4.0')
meta_kernels.add_new_kernel('focal', ['linux-raspi'], '-5.4.0', signed=False)
meta_kernels.add_new_kernel('focal', ['linux-raspi2'], '-5.4.0', signed=False)
meta_kernels.add_new_kernel('focal', ['linux-oem-5.6'], '-5.6.0')
meta_kernels.add_new_kernel('focal', ['linux-oem-5.10'], '-5.10.0')
meta_kernels.add_new_kernel('focal', ['linux-oem-5.13'], '-5.13.0')
meta_kernels.add_new_kernel('focal', ['linux-oem-5.14'], '-5.14.0')
meta_kernels.add_new_kernel('focal', ['linux-aws'], '-5.4.0')
meta_kernels.add_new_kernel('focal', ['linux-aws-5.8'], '-5.8.0', signed=False)
meta_kernels.add_new_kernel('focal', ['linux-aws-5.11'], '-5.11.0', signed=False)
meta_kernels.add_new_kernel('focal', ['linux-aws-5.13'], '-5.13.0')
meta_kernels.add_new_kernel('focal', ['linux-aws-5.15'], '-5.15.0')
meta_kernels.add_new_kernel('focal', ['linux-azure'], '-5.4.0')   # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('focal', ['linux-azure-5.8'], '-5.8.0')   # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('focal', ['linux-azure-5.11'], '-5.11.0')   # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('focal', ['linux-azure-5.13'], '-5.13.0')   # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('focal', ['linux-azure-5.15'], '-5.15.0')   # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('focal', ['linux-bluefield'], '-5.4.0')
meta_kernels.add_new_kernel('focal', ['linux-azure-fde'], '-5.4.0')   # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('focal', ['linux-gcp'], '-5.4.0')  # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('focal', ['linux-gcp-5.8'], '-5.8.0')  # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('focal', ['linux-gcp-5.11'], '-5.11.0')  # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('focal', ['linux-gcp-5.13'], '-5.13.0')  # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('focal', ['linux-gcp-5.15'], '-5.15.0')  # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('focal', ['linux-gke'], '-5.4.0')
meta_kernels.add_new_kernel('focal', ['linux-gke-5.15'], '-5.15.0')
meta_kernels.add_new_kernel('focal', ['linux-gkeop'], '-5.4.0')
meta_kernels.add_new_kernel('focal', ['linux-ibm'], '-5.4.0')
meta_kernels.add_new_kernel('focal', ['linux-intel-5.13'], '-5.13.0')
# the linux-intel-iotg-5.15 is still only in edge status
# meta_kernels.add_new_kernel('focal', ['linux-intel-iotg-5.15'], '-5.15.0')
meta_kernels.add_new_kernel('focal', ['linux-kvm'], '-5.4.0')
meta_kernels.add_new_kernel('focal', ['linux-oracle'], '-5.4')
meta_kernels.add_new_kernel('focal', ['linux-oracle-5.8'], '-5.8')
meta_kernels.add_new_kernel('focal', ['linux-oracle-5.11'], '-5.11')
meta_kernels.add_new_kernel('focal', ['linux-oracle-5.13'], '-5.13')
meta_kernels.add_new_kernel('focal', ['linux-oracle-5.15'], '-5.15')
meta_kernels.add_new_kernel('focal', ['linux-riscv'], '-5.4', signed=False)
meta_kernels.add_new_kernel('focal', ['linux-riscv-5.8'], '-5.8', signed=False)
meta_kernels.add_new_kernel('focal', ['linux-riscv-5.11'], '-5.8', signed=False)
meta_kernels.add_new_kernel('focal', ['linux-hwe-5.8'], '-5.8.0')
meta_kernels.add_new_kernel('focal', ['linux-hwe-5.11'], '-5.11.0')
meta_kernels.add_new_kernel('focal', ['linux-hwe-5.13'], '-5.13.0')
meta_kernels.add_new_kernel('focal', ['linux-hwe-5.15'], '-5.15.0')
meta_kernels.add_new_kernel('focal', ['linux-lowlatency-hwe-5.15'], '-5.15.0')
meta_kernels.add_new_kernel('groovy', ['linux'], '-5.8.0')
meta_kernels.add_new_kernel('groovy', ['linux-raspi'], '-5.8.0', signed=False)
meta_kernels.add_new_kernel('groovy', ['linux-aws'], '-5.8.0', signed=False)
meta_kernels.add_new_kernel('groovy', ['linux-azure'], '-5.8.0')   # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('groovy', ['linux-gcp'], '-5.8.0')  # suffix may need to change, but it looks like it is ignored
meta_kernels.add_new_kernel('groovy', ['linux-kvm'], '-5.8.0')
meta_kernels.add_new_kernel('groovy', ['linux-oracle'], '-5.8')
meta_kernels.add_new_kernel('groovy', ['linux-riscv'], '-5.8', signed=False)
meta_kernels.add_new_kernel('hirsute', ['linux'], '-5.11.0')
meta_kernels.add_new_kernel('hirsute', ['linux-raspi'], '-5.11.0', signed=False)
meta_kernels.add_new_kernel('hirsute', ['linux-aws'], '-5.11.0', signed=False)
meta_kernels.add_new_kernel('hirsute', ['linux-azure'], '-5.11.0')
meta_kernels.add_new_kernel('hirsute', ['linux-gcp'], '-5.11.0')
meta_kernels.add_new_kernel('hirsute', ['linux-kvm'], '-5.11.0')
meta_kernels.add_new_kernel('hirsute', ['linux-oracle'], '-5.11')
meta_kernels.add_new_kernel('hirsute', ['linux-riscv'], '-5.11', signed=False)
meta_kernels.add_new_kernel('impish', ['linux'], '-5.13.0')
meta_kernels.add_new_kernel('impish', ['linux-raspi'], '-5.13.0', signed=False)
meta_kernels.add_new_kernel('impish', ['linux-aws'], '-5.13.0')
meta_kernels.add_new_kernel('impish', ['linux-azure'], '-5.13.0')
meta_kernels.add_new_kernel('impish', ['linux-gcp'], '-5.13.0')
meta_kernels.add_new_kernel('impish', ['linux-kvm'], '-5.13.0')
meta_kernels.add_new_kernel('impish', ['linux-oracle'], '-5.13')
meta_kernels.add_new_kernel('impish', ['linux-riscv'], '-5.13', signed=False)
meta_kernels.add_new_kernel('jammy', ['linux'], '-5.15.0')
meta_kernels.add_new_kernel('jammy', ['linux-raspi'], '-5.15.0', signed=False)
meta_kernels.add_new_kernel('jammy', ['linux-aws'], '-5.15.0')
meta_kernels.add_new_kernel('jammy', ['linux-azure'], '-5.15.0')
meta_kernels.add_new_kernel('jammy', ['linux-azure-5.19'], '-5.19.0')
meta_kernels.add_new_kernel('jammy', ['linux-azure-fde'], '-5.15.0')
meta_kernels.add_new_kernel('jammy', ['linux-gcp'], '-5.15.0')
meta_kernels.add_new_kernel('jammy', ['linux-gke'], '-5.15.0')
meta_kernels.add_new_kernel('jammy', ['linux-gkeop'], '-5.15.0')
meta_kernels.add_new_kernel('jammy', ['linux-hwe-5.19'], '-5.19.0')
meta_kernels.add_new_kernel('jammy', ['linux-ibm'], '-5.15.0')
meta_kernels.add_new_kernel('jammy', ['linux-intel-iotg'], '-5.15.0')
meta_kernels.add_new_kernel('jammy', ['linux-kvm'], '-5.15.0')
meta_kernels.add_new_kernel('jammy', ['linux-lowlatency'], '-5.15.0')
meta_kernels.add_new_kernel('jammy', ['linux-lowlatency-hwe-5.19'], '-5.19.0')
meta_kernels.add_new_kernel('jammy', ['linux-oem-5.17'], '-5.17.0')
meta_kernels.add_new_kernel('jammy', ['linux-oem-6.0'], '-6.0.0')
meta_kernels.add_new_kernel('jammy', ['linux-oem-6.1'], '-6.1.0')
meta_kernels.add_new_kernel('jammy', ['linux-oracle'], '-5.15')
meta_kernels.add_new_kernel('jammy', ['linux-riscv'], '-5.15', signed=False)
meta_kernels.add_new_kernel('kinetic', ['linux'], '-5.19.0')
meta_kernels.add_new_kernel('kinetic', ['linux-lowlatency'], '-5.19.0')
meta_kernels.add_new_kernel('kinetic', ['linux-raspi'], '-5.19.0', signed=False)
meta_kernels.add_new_kernel('kinetic', ['linux-aws'], '-5.19.0')
meta_kernels.add_new_kernel('kinetic', ['linux-azure'], '-5.19.0')
meta_kernels.add_new_kernel('kinetic', ['linux-gcp'], '-5.19.0')
meta_kernels.add_new_kernel('kinetic', ['linux-ibm'], '-5.19.0')
meta_kernels.add_new_kernel('kinetic', ['linux-kvm'], '-5.19.0')
meta_kernels.add_new_kernel('kinetic', ['linux-oracle'], '-5.19')
meta_kernels.add_new_kernel('kinetic', ['linux-riscv'], '-5.19', signed=False)
meta_kernels.add_new_kernel('lunar', ['linux'], '-6.2.0')
meta_kernels.add_new_kernel('lunar', ['linux-lowlatency'], '-6.2.0')
meta_kernels.add_new_kernel('lunar', ['linux-raspi'], '-6.2.0', signed = False)
meta_kernels.add_new_kernel('lunar', ['linux-aws'], '-6.2.0')
meta_kernels.add_new_kernel('lunar', ['linux-azure'], '-6.2.0')
meta_kernels.add_new_kernel('lunar', ['linux-gcp'], '-6.2.0')
meta_kernels.add_new_kernel('lunar', ['linux-ibm'], '-6.2.0')
meta_kernels.add_new_kernel('lunar', ['linux-kvm'], '-6.2.0')
meta_kernels.add_new_kernel('lunar', ['linux-oracle'], '-6.2.0')
meta_kernels.add_new_kernel('lunar', ['linux-riscv'], '-6.2.0', signed = False)

# list of kernel versions to masquerade as when things end up in the
# wrong pockets or otherwise should not have a USN published for it.
# Data structure format:
#   '$KERNEL':
#       "$RELEASE": {
#           'LAST USN VERSION': 'CURRENT VERSION IN SECURITY'
#       }
#   }
#
kernel_glitches = {
    'linux': {
        'maverick': {
            '2.6.35-28.49': '2.6.35-28.50'
        },
        'precise': {
            '3.2.0-105.146': '3.2.0-106.147'
        },
        'trusty': {
            '3.13.0-49.81': '3.13.0-49.83',
            '3.13.0-166.216': '3.13.0-167.217',
        },
        'utopic': {
            '~': '3.16.0-44.59'
        },
        'xenial': {
            '4.4.0-28.47': '4.4.0-31.50',
            '4.4.0-210.242': '4.4.0-211.243',  # Bugfix only update
            '4.4.0-216.249': '4.4.0-217.250',  # LP: #1939915
        },
        'zesty': {
            '~': '4.10.0-20.22'
        },
        'artful': {  # artful update to disable spi driver
            '4.13.0-19.22': '4.13.0-21.24'
        },
        'bionic': {  # bionic: LP: #1938013
            '4.15.0-151.157': '4.15.0-153.160',
            '4.15.0-194.205': '4.15.0-196.207', # LP: #1994601
        },
        'disco': {  # disco i386 PTI regression fix
            '5.0.0-21.22': '5.0.0-23.24',
        },
        'focal': {
            '5.4.0-28.32': '5.4.0-29.33',  # signed nvidia modules regression fix (LP: #1875888)
        },
    },
    'linux-aws': {  # linux-aws
        'trusty': {
            '4.4.0-1009.9': '4.4.0-1010.10',
            '4.4.0-1092.96': '4.4.0-1093.97',
            '4.4.0-1096.101': '4.4.0-1097.102',  # LP: #1939915
            '4.4.0-1103.108': '4.4.0-1104.109',
        },
        'xenial': {
            '5.4.0-1047.56': '4.4.0-1048.57',
            '4.4.0-1128.142': '4.4.0-1129.143',
            '4.4.0-1132.146': '4.4.0-1133.147',  # LP: #1939915
        },
        'bionic': {
            '4.15.0-1033.35': '4.15.0-1034.36',
            '4.15.0-1086.91': '4.15.0-1087.92',
            '4.15.0-1099.106': '4.15.0-1101.108',
        },
        'cosmic': {
            '4.18.0-1008.10': '4.18.0-1011.13',
        },
        'focal': {
            '5.4.0-1020.20': '5.4.0-1021.21',
            '5.4.0-1028.29': '5.4.0-1029.30',
            '5.4.0-1045.47': '5.4.0-1047.49',
        },
    },
    'linux-aws-5.0': {  # linux-aws
        'bionic': {
            '~': '5.0.0-1021.24~18.04.1',  # initial publication
        },
    },
    'linux-aws-5.3': {  # linux-aws
        'bionic': {
            '~': '5.3.0-1017.18~18.04.1',  # initial publication
        },
    },
    'linux-aws-5.4': {  # linux-aws
        'bionic': {
            '5.4.0-1028.29~18.04.1': '5.4.0-1029.30~18.04.1',  # initial publication
            '5.4.0-1045.47~18.04.1': '5.4.0-1047.49~18.04.1',  # initial publication
        },
    },
    'linux-aws-5.8': {  # linux-aws
        'focal': {
            '~': '5.8.0-1035.37~20.04.1',  # initial publication
        },
    },
    'linux-aws-5.11': {  # linux-aws
        'focal': {
            '~': '5.11.0-1016.17~20.04.1',  # initial publication
        },
    },
    'linux-aws-5.13': {  # linux-aws
        'focal': {
            '~': '5.13.0-1011.12~20.04.1',  # initial publication
            '5.13.0-1028.31~20.04.1': '5.13.0-1029.32~20.04.1',  # LP: #1973620 fix
        },
    },
    'linux-aws-5.15': {  # linux-aws
        'focal': {
            '~': '5.15.0-1015.19~20.04.1',  # initial publication
        },
    },
    'linux-aws-hwe': {  # linux-aws-hwe
        'xenial': {
            '4.15.0-1035.37~16.04.1': '4.15.0-1039.41~16.04.1',
            '4.15.0-1043.45~16.04.1': '4.15.0-1044.46~16.04.1',
        },
    },
    'linux-azure': {
        'trusty': {
            '4.15.0-1037.39~14.04.2': '4.15.0-1039.41~14.04.2',
            '4.15.0-1063.68~14.04.1': '4.15.0-1064.69~14.04.1',
        },
        'xenial': {
            '4.15.0-1037.39~16.04.1': '4.15.0-1039.43',
            '4.15.0-1045.49': '4.15.0-1046.50',
            '4.15.0-1047.51': '4.15.0-1049.54',
            '4.15.0-1049.54': '4.15.0-1050.55',
            '4.15.0-1050.55': '4.15.0-1051.56',
            '4.15.0-1051.56': '4.15.0-1052.57',
            '4.15.0-1063.68': '4.15.0-1064.69',
            '4.15.0-1066.71': '4.15.0-1067.72',
            '4.15.0-1067.72': '4.15.0-1069.74',
            '4.15.0-1113.126~16.04.1': '4.15.0-1114.127~16.04.1',
        },
        'bionic': {
            '4.15.0-1037.39': '4.18.0-1011.11~18.04.1',
            '4.18.0-1018.18~18.04.1': '4.18.0-1019.19~18.04.1',
            '4.18.0-1023.24~18.04.1': '4.18.0-1024.25~18.04.1',
            '4.18.0-1024.25~18.04.1': '4.18.0-1025.27~18.04.1',
            '5.0.0-1014.14~18.04.1': '5.0.0-1016.17~18.04.1',
            '5.0.0-1020.21~18.04.1': '5.0.0-1022.23~18.04.1',
            '5.0.0-1025.27~18.04.1': '5.0.0-1027.29~18.04.1',
            '5.0.0-1028.30~18.04.1': '5.0.0-1029.31~18.04.1',
            '5.0.0-1029.31~18.04.1': '5.0.0-1031.33',
        },
        'cosmic': {
            '4.18.0-1008.8': '4.18.0-1011.11',
            '4.18.0-1018.18': '4.18.0-1019.19',
            '4.18.0-1023.24': '4.18.0-1024.25',
        },
        'disco': {
            '5.0.0-1006.6': '5.0.0-1008.8',
            '5.0.0-1010.10': '5.0.0-1011.11',
            '5.0.0-1014.14': '5.0.0-1016.17',
            '5.0.0-1025.27': '5.0.0-1027.29',
        },
        'eoan': {
            '5.3.0-1007.8': '5.3.0-1008.9',
            '5.3.0-1009.10': '5.3.0-1010.11',
            '5.3.0-1010.11': '5.3.0-1012.13',
        },
        'jammy': {
            '5.15.0-1023.29': '5.15.0-1024.30', # no security fixes
        },
    },
    'linux-azure-4.15': {
        'bionic': {
            '~': '4.15.0-1082.92',  # initial publication
        },
    },
    'linux-azure-5.3': {
        'bionic': {
            '~': '5.3.0-1007.8~18.04.1',  # initial publication
            '5.3.0-1007.8~18.04.1': '5.3.0-1008.9~18.04.1',
            '5.3.0-1009.10~18.04.1': '5.3.0-1010.11~18.04.1',
            '5.3.0-1010.11~18.04.1': '5.3.0-1012.13~18.04.1',
        },
    },
    'linux-azure-5.4': {
        'bionic': {
            '~': '5.4.0-1020.20~18.04.1',  # initial publication
        },
    },
    'linux-azure-5.8': {
        'focal': {
            '~': '5.8.0-1033.35~20.04.1',  # initial publication
        },
    },
    'linux-azure-5.11': {
        'focal': {
            '~': '5.11.0-1013.14~20.04.1',  # initial publication
        },
    },
    'linux-azure-5.13': {
        'focal': {
            '5.13.0-1028.33~20.04.1': '5.13.0-1029.34~20.04.1',  # LP: #1973620 fix
        },
    },
    'linux-azure-5.15': {
        'focal': {
            '~': '5.15.0-1014.17~20.04.1',  # initial publication
        },
    },
    'linux-azure-5.19': {
        'jammy': {
            '~': '5.19.0-1021.22~22.04.1',  # initial publication
            '5.19.0-1021.22~22.04.1': '5.19.0.1022.23~22.04.1', # only edge binaries
        },
    },
    'linux-azure-fde': {
        'focal': {
            '~': '5.4.0-1069.72+cvm1.1',  # initial publication
            '5.4.0-1085.90+cvm1.1': '5.4.0-1085.90+cvm2.1',  # fix for LP: #1980023
        },
        'jammy': {
            '~': '5.15.0-1019.24.1',  # initial publication
        },
    },
    'linux-bluefield': {
        'focal': {
            '~': '5.4.0-1016.19',  # initial publication
            '5.4.0-1016.19': '5.4.0-1019.22',
            '5.4.0-1032.35': '5.4.0-1035.38',
            '5.4.0-1036.39': '5.4.0-1040.44',
        },
    },
    'linux-euclid': {
        'xenial': {
            '4.4.0-9027.29': '4.4.0-9028.30'
        },
    },
    'linux-dell300x': {
        'bionic': {
            '~': '4.15.0-1011.15',  # initial publication
        },
    },
    'linux-gcp': {  # linux-gcp
        'xenial': {
            '~': '4.10.0-1006.6',  # initial publication
            '4.15.0-1032.34~16.04.1': '4.15.0-1033.35~16.04.1',
            '4.15.0-1044.46': '4.15.0-1046.49',
        },
        'bionic': {
            '4.15.0-1040.42': '4.15.0-1042.45',
            '4.15.0-1044.70': '5.0.0-1020.20~18.04.1',
            '5.0.0-1026.27~18.04.1': '5.0.0-1028.29~18.04.1',
        },
    },
    'linux-gcp-4.15': {  # linux-gcp
        'bionic': {
            '~': '4.15.0-1077.87',  # initial publication
        },
    },
    'linux-gcp-5.3': {  # linux-gcp
        'bionic': {
            '~': '5.3.0-1008.9~18.04.1',  # initial publication
        },
    },
    'linux-gcp-5.8': {  # linux-gcp
        'focal': {
            '~': '5.8.0-1032.34~20.04.1',  # initial publication
        },
    },
    'linux-gcp-5.11': {  # linux-gcp
        'focal': {
            '~': '5.11.0-1020.22~20.04.1',  # initial publication
        },
    },
    'linux-gcp-5.13': {  # linux-gcp
        'focal': {
            '~': '5.13.0-1013.16~20.04.1',  # initial publication
            '5.13.0-1030.36~20.04.1': '5.13.0-1031.37~20.04.1',  # LP: #1973620 fix
        },
    },
    'linux-gcp-5.15': {  # linux-gcp
        'focal': {
            '~': '5.15.0-1013.18~20.04.1',  # initial publication
        },
    },
    'linux-gke': {  # linux-gke
        'xenial': {
            '~': '4.4.0-1003.3'
        },
        'focal': {
            '~': '5.4.0-1042.44',
        },
    },
    'linux-gke-4.15': {  # linux-gke-4.15
        'bionic': {
            '~': '4.15.0-1034.36',
            '4.15.0-1036.38': '4.15.0-1037.39',
            '4.15.0-1044.46': '4.15.0-1045.48',
        },
    },
    'linux-gke-5.0': {
        'bionic': {
            '~': '5.0.0-1013.13~18.04.1',
            '5.0.0-1020.20~18.04.1': '5.0.0-1022.22~18.04.3',
            '5.0.0-1049.50': '5.0.0-1050.52',
        },
    },
    'linux-gke-5.3': {
        'bionic': {
            '~': '5.3.0-1012.13~18.04.1',
            '5.3.0-1016.17~18.04.1': '5.3.0-1017.18~18.04.1',
        },
    },
    'linux-gke-5.4': {
        'bionic': {
            '~': '5.4.0-1029.31~18.04.1',
            '5.4.0-1029.31~18.04.1': '5.4.0-1032.34~18.04.1',
            '5.4.0-1068.71~18.04.1': '5.4.0-1071.76~18.04.3',
        },
    },
    'linux-gke-5.15': {
        'focal': {
            '~': '5.15.0-1011.14~20.04.1', # initial publication
        },
    },
    'linux-gkeop': {
        'focal': {
            '~': '5.4.0-1009.10',
        },
        'jammy': {
            '~': '5.15.0-1001.2',  # Initial publication
            '5.15.0-1004.6': '5.15.0-1005.7', # config update
        },
    },
    'linux-gkeop-5.4': {
        'bionic': {
            '~': '5.4.0-1007.8~18.04.1',
            '5.4.0-1007.8~18.04.1': '5.4.0-1008.9~18.04.1',
        },
    },
    'linux-ibm': {
        'focal': {
            '~': '5.4.0-1005.6',
        },
    },
    'linux-ibm-5.4': {
        'bionic': {
            '~': '5.4.0-1014.15~18.04.1',
        },
    },
    'linux-intel-5.13': {
        'focal': {
            '~': '5.13.0-1004.4',  # initial publication
            '5.13.0-1004.4': '5.13.0-1008.8',  # Still trailing other 5.13 kernels
            '5.13.0-1008.8': '5.13.0-1009.9',  # not sure what's up with this kernel
        },
    },
    'linux-lowlatency-hwe-5.15': {
        'focal': {
            '~': '5.15.0-42.45~20.04.1',  # initial publication
        },
    },
    'linux-lowlatency-hwe-5.19': {
        'jammy': {
            '~': ' 5.19.0-1017.18~22.04.1',  # initial publication
        },
    },
    'linux-kvm': {
        'xenial': {
            '4.4.0-1093.102': '4.4.0-1094.103',
            '4.4.0-1097.106': '4.4.0-1098.107',  # LP: #1939915
        },
        'bionic': {
            '4.15.0-1092.94': '4.15.0-1094.96',
        },
    },
    'linux-oem': {
        'xenial': {
            '4.13.0-1031.35': '4.13.0-1032.36',
        },
        'bionic': {
            '4.15.0-1006.9': '4.15.0-1008.11',
            '4.15.0-1017.20': '4.15.0-1018.21',
            '4.15.0-1026.31': '4.15.0-1028.33',
            '4.15.0-1067.77': '4.15.0-1069.79',
            '4.15.0-1069.79': '4.15.0-1073.83',
        },
        'cosmic': { # cosmic kernels are forward copies from bionic
            '~': '4.15.0-1033.38',
            '4.15.0-1033.38': '4.15.0-1034.39',
            '4.15.0-1034.39': '4.15.0-1035.40',
            '4.15.0-1035.40': '4.15.0-1038.43',
            '4.15.0-1038.43': '4.15.0-1039.44',
            '4.15.0-1039.44': '4.15.0-1043.48',
            '4.15.0-1043.48': '4.15.0-1045.50',
        },
        'disco': { # disco kernels are forward copies from bionic
            '~': '4.15.0-1038.43',
            '4.15.0-1038.43': '4.15.0-1039.44',
            '4.15.0-1039.44': '4.15.0-1043.48',
            '4.15.0-1043.48': '4.15.0-1045.50',
            '4.15.0-1045.50': '4.15.0-1050.57',
        }
    },
    'linux-oem-5.6': {
        'focal': {
            '~': '5.6.0-1021.21',
            '5.6.0-1021.21': '5.6.0-1036.39',
            '5.6.0-1048.52': '5.6.0-1050.54',
        },
    },
    'linux-oem-osp1': {
        'bionic': {
            '~': '5.0.0-1025.28',
            '5.0.0-1033.38': '5.0.0-1037.42',
            '5.0.0-1037.42': '5.0.0-1039.44',
            '5.0.0-1039.44': '5.0.0-1040.45',
            '5.0.0-1043.48': '5.0.0-1046.51',
        },
    },
    'linux-oem-5.10': {
        'focal': {
            '~': '5.10.0-1013.14',  # initial publication
            '5.10.0-1014.15': '5.10.0-1016.17',
            '5.10.0-1022.23': '5.10.0-1023.24',
            '5.10.0-1038.40': '5.10.0-1044.46',
        },
    },
    'linux-oem-5.13': {
        'focal': {
            '~': '5.13.0-1011.15',  # initial publication
        },
    },
    'linux-oem-5.14': {
        'focal': {
            '~': '5.14.0-1005.5',  # initial publication
            '5.14.0-1050.57': '5.14.0-1051.58',  # regression fix LP: #1987690
        },
    },
    'linux-oem-5.17': {
        'jammy': {
            '5.17.0-1011.12': '5.17.0-1012.13',
            '5.17.0-1020.21': '5.17.0-1021.22', # no security fixes, LP: #1992020
        },
    },
    'linux-oem-6.0': {
        'jammy': {
            '~': '6.0.0-1007.7',  # Initial publication
        },
    },
    'linux-oem-6.1': {
        'jammy': {
            '~': '6.1.0-1004.4',  # Initial publication
        },
    },
    'linux-oracle': {
        'xenial': {
            '~': '4.15.0-1008.10~16.04.1',
            '4.15.0-1017.19~16.04.2': '4.15.0-1018.20~16.04.1',
        },
        'bionic': {
            '~': '4.15.0-1008.10',
        },
        'disco': {  # disco kernels are carried forward from bionic
            '~': '4.15.0-1013.15',
            '4.15.0-1013.15': '4.15.0-1014.16',
            '4.15.0-1014.16': '4.15.0-1015.17',
            '4.15.0-1015.17': '4.15.0-1016.18',
            '4.15.0-1016.18': '4.15.0-1017.19',
            '4.15.0-1017.19': '4.15.0-1018.20',
            '4.15.0-1018.20': '5.0.0-1004.8',
            '5.0.0-1004.8': '5.0.0-1005.9', # sarnold forgot
        },
        'eoan': {
            '~': '5.3.0-1003.3',
        },
    },
    'linux-oracle-5.0': {
        'bionic': {
            '~': '5.0.0-1007.12~18.04.1',  # initial publication
        },
    },
    'linux-oracle-5.3': {
        'bionic': {
            '~': '5.3.0-1011.12~18.04.1',  # initial publication
        },
    },
    'linux-oracle-5.8': {
        'focal': {
            '~': '5.8.0-1031.32~20.04.2',  # initial publication
        },
    },
    'linux-oracle-5.11': {
        'focal': {
            '~': '5.11.0-1016.17~20.04.1',  # initial publication
        },
    },
    'linux-oracle-5.13': {
        'focal': {
            '~': '5.13.0-1016.20~20.04.1',  # initial publication
            '5.13.0-1027.32~20.04.1': '5.13.0-1028.33~20.04.1',  # initial publication
            '5.13.0-1033.39~20.04.1': '5.13.0-1034.40~20.04.1',  # LP: #1973620 fix
        },
    },
    'linux-oracle-5.15': {
        'focal': {
            '~': '5.15.0-1021.27~20.04.1',  # initial publication
        },
    },

    'linux-exynos5': {  # oem linux-exynos5 accidentally miscopied to security
        'trusty': {
            '~': '3.13.0-5.6'
        }
    },
    'linux-raspi2': {  # meltdown updates did not apply to linux-raspi2
        'xenial': {
            '4.4.0-1080.88': '4.4.0-1082.90',
            '4.4.0-1124.133': '4.4.0-1125.134',
            '4.4.0-1129.138': '4.4.0-1130.139',  # kernel fixed intel only issue
        },
        'bionic': {
            '4.15.0-1013.14': '4.15.0-1017.18',
            '4.15.0-1049.53': '4.15.0-1050.54',
            '4.15.0-1053.57': '4.15.0-1054.58',
            '4.15.0-1074.79': '4.15.0-1076.81',
            '4.15.0-1092.98': '4.15.0-1093.99',  # LP: #1938013
            '4.15.0-1107.114': '4.15.0-1108.115',  # LP: #1938013
        },
        'eoan': {
            '5.3.0-1012.14': '5.3.0-1014.16',
            '5.3.0-1015.17': '5.3.0-1017.19',
        },
    },
    'linux-raspi2-5.3': {
        'bionic': {
            '~': '5.3.0-1017.19~18.04.1',  # initial publication
        },
    },
    'linux-raspi-5.4': {
        'bionic': {
            '~': '5.4.0-1013.13~18.04.1',  # initial publication
        },
    },
    'linux-riscv': {
        # linux-riscv is problematic for USN publications because the
        # meta package used for it is linux-image-generic but with a
        # different version than the primary kernel's
        # linux-image-generic, and our USN publishing process does not
        # handle different architectures having different versions for
        # the same binary package well.
        'focal': {
            '5.4.0-30.34': '5.4.0-31.35',  # initial publication
            '5.4.0-31.35': '5.4.0-33.37',
            '5.4.0-33.37': '5.4.0-34.38',
            '5.4.0-34.38': '5.4.0-36.41',
            '5.4.0-36.41': '5.4.0-37.42',
            '5.4.0-37.42': '5.4.0-39.44',
            '5.4.0-39.44': '5.4.0-40.45',
        },
        'groovy': {
            '~': '5.8.0-8.9',  # initial publication
            '5.8.0-8.9': '5.8.0-10.12',
            '5.8.0-10.12': '5.8.0-12.14',
            '5.8.0-12.14': '5.8.0-13.15',
            '5.8.0-13.15': '5.8.0-14.16',
            '5.8.0-14.16': '5.8.0-16.18',
            '5.8.0-16.18': '5.8.0-17.19',
            '5.8.0-17.19': '5.8.0-18.20',
            '5.8.0-18.20': '5.8.0-20.22',
            '5.8.0-20.22': '5.8.0-22.24',
            '5.8.0-22.24': '5.8.0-25.27',
            '5.8.0-25.27': '5.8.0-26.28',
            '5.8.0-26.28': '5.8.0-29.31',
            '5.8.0-29.31': '5.8.0-32.35',
        },
        'hirsute': {
            '~': '5.11.0-1008.8',  # initial publication
            '5.11.0-1008.8': '5.11.0-1009.9',
            '5.11.0-1009.9': '5.11.0-1012.12',
            '5.11.0-1012.12': '5.11.0-1015.16',
            '5.11.0-1015.16': '5.11.0-1017.18',
            '5.11.0-1017.18': '5.11.0-1018.19',
            '5.11.0-1018.19': '5.11.0-1020.21',
            '5.11.0-1020.21': '5.11.0-1021.22',
            '5.11.0-1021.22': '5.11.0-1022.23',
            '5.11.0-1022.23': '5.11.0-1023.24',
            '5.11.0-1023.24': '5.11.0-1024.25',
            '5.11.0-1024.25': '5.11.0-1026.28',
            '5.11.0-1026.28': '5.11.0-1028.31',
        },
        'impish': {
            '~': '5.13.0-1005.5',  # initial publication
            '5.13.0-1005.5': '5.13.0-1006.6',
            '5.13.0-1006.6': '5.13.0-1007.7',
            '5.13.0-1007.7': '5.13.0-1008.8',
            '5.13.0-1008.8': '5.13.0-1010.11',
            '5.13.0-1010.11': '5.13.0-1011.12',
            '5.13.0-1011.12': '5.13.0-1012.14',
            '5.13.0-1012.14': '5.13.0-1015.17',
            '5.13.0-1015.17': '5.13.0-1017.19',
            '5.13.0-1017.19': '5.13.0-1019.21',
            '5.13.0-1019.21': '5.13.0-1020.22',
            '5.13.0-1020.22': '5.13.0-1021.23',
            '5.13.0-1021.23': '5.13.0-1023.25',
            '5.13.0-1023.25': '5.13.0-1026.29',
        },
        'jammy': {
            '~': '5.15.0-1008.8',  # initial publication
            '5.15.0-1008.8': '5.15.0-1011.12',
            '5.15.0-1011.12': '5.15.0-1014.16',
            '5.15.0-1014.16': '5.15.0-1015.17',
            '5.15.0-1015.17': '5.15.0-1016.18',
            '5.15.0-1016.18': '5.15.0-1017.19',
            '5.15.0-1017.19': '5.15.0-1018.21',
            '5.15.0-1018.21': '5.15.0-1019.22',
            '5.15.0-1019.22': '5.15.0-1020.23',
            '5.15.0-1020.23': '5.15.0-1022.26',
            '5.15.0-1022.26': '5.15.0-1023.27',
            '5.15.0-1023.27': '5.15.0-1026.30',
            '5.15.0-1026.30': '5.15.0-1027.31',
            '5.15.0-1027.31': '5.15.0-1028.32',
        },
        'kinetic': {
            '~': '5.19.0-1006.7',  # initial publication
            '5.19.0-1006.7':  '5.19.0-1009.10',
            '5.19.0-1009.10': '5.19.0-1011.12',
            '5.19.0-1011.12': '5.19.0-1012.13',
            '5.19.0-1012.13': '5.19.0-1013.14',
            '5.19.0-1013.14': '5.19.0-1015.16',
            '5.19.0-1015.16': '5.19.0-1016.17',
            '5.19.0-1016.17': '5.19.0-1017.18',
        },
    },
    'linux-riscv-5.8': {
        'focal': {
            '~': '5.8.0-26.28~20.04.1',  # initial publication
            '5.8.0-26.28~20.04.1': '5.8.0-29.31~20.04.1'
        },
    },
    'linux-riscv-5.11': {
        'focal': {
            '~': '5.11.0-1017.18~20.04.1',  # initial publication
            '5.11.0-1017.18~20.04.1': '5.11.0-1018.19~20.04.2',
            '5.11.0-1018.19~20.04.2': '5.11.0-1020.21~20.04.1',
            '5.11.0-1020.21~20.04.1': '5.11.0-1021.22~20.04.1',
            '5.11.0-1021.22~20.04.1': '5.11.0-1022.23~20.04.1',
            '5.11.0-1022.23~20.04.1': '5.11.0-1023.24~20.04.1',
            '5.11.0-1023.24~20.04.1': '5.11.0-1024.25~20.04.1',
            '5.11.0-1024.25~20.04.1': '5.11.0-1026.28~20.04.1',
            '5.11.0-1026.28~20.04.1': '5.11.0-1028.31~20.04.1',
            '5.11.0-1028.31~20.04.1': '5.11.0-1029.32~20.04.1',
            '5.11.0-1029.32~20.04.1': '5.11.0-1030.34',
            '5.11.0-1030.34': '5.11.0-1031.35',
        },
    },
    'linux-ti-omap4': {
        'precise': {
            '3.2.0-1483.110': '3.2.0-1484.111'
        },
    },
    'linux-keystone': {  # oem linux-keystone added post-release and
                         #  no USNs, so use '~', '<version in security>
        'trusty': {
            # '~': '3.13.0-43.68'
            '~': '3.13.0-68.96',
        },
    },
    'linux-snapdragon': {  # meltdown updates did not apply to linux-snapdragon
        'xenial': {
            '4.4.0-1081.86': '4.4.0-1084.89',
            '4.4.0-1118.124': '4.4.0-1121.127',
            '4.4.0-1128.136': '4.4.0-1129.137',
            '4.4.0-1133.141': '4.4.0-1134.142',  # kernel fixed intel only issue
        },
        'yakkety': {
            '~': '4.4.0-1063.68'
        },
        'zesty': {
            '~': '4.4.0-1081.86'
        },
        'artful': {
            '~': '4.4.0-1095.100'
        },
        'bionic': {
            '4.15.0-1060.66': '4.15.0-1062.69',
            '4.15.0-1066.73': '4.15.0-1067.74',
            '4.15.0-1070.77': '4.15.0-1071.78',
            '4.15.0-1109.118': '4.15.0-1110.119',  # LP: #1938013
        },
        'disco': {
            '~': '5.0.0-1012.12',
        },
    },
    'linux-lts-utopic': {  # first release of utopic backport kernel
        'trusty': {
            # '~': '3.16.0-25.33~14.04.2'
            '3.16.0-46.62~14.04.1': '3.16.0-49.65~14.04.1'
        }
    },
    'linux-lts-vivid': {  # zombie vivid lives on
        'trusty': {
            '3.19.0-66.74~14.04.1': '3.19.0-80.88~14.04.1',
        }
    },
    'linux-lts-wily': {  # wily lts accidentally miscopied to security
        'trusty': {
            '4.2.0-18.22~14.04.1': '4.2.0-19.23~14.04.1',
        }
    },
    'linux-lts-xenial': {
        'trusty': {
            # only change in 4.4.0-112.135~14.04.1 is NOBP config for s390x,
            # which is not a supported arch for Ubuntu 14.04 LTS.
            '4.4.0-111.134~14.04.1': '4.4.0-112.135~14.04.1',
            '4.4.0-210.242~14.04.1': '4.4.0-211.243~14.04.1',
            '4.4.0-214.246~14.04.1': '4.4.0-215.247~14.04.1',  # LP: #1939915
        }
    },
    'linux-hwe': {  # hwe kernel initial publication
        'xenial': {
            '~': '4.8.0-39.42~16.04.1',
            '4.15.0-151.157~16.04.1': '4.15.0-153.160~16.04.1',  # LP: #1938013
            '4.15.0-194.205~16.04.1': '4.15.0-196.207~16.04.1',  # LP: #1994601
        },
        'bionic': {
            '~': '4.18.0-13.14~18.04.1',
        },
    },
    'linux-hwe-5.4': {  # hwe kernel initial publication
        'bionic': {
            '~': '5.4.0-40.44~18.04.1',
        },
    },
    'linux-hwe-5.8': {
        'focal': {
            '~': '5.8.0-33.36~20.04.1',  # hwe kernel initial publication
        },
    },
    'linux-hwe-5.11': {
        'focal': {
            '5.11.0-41.45~20.04.1': '5.11.0-43.47~20.04.2',  # LP: #1949063
        },
    },
    'linux-hwe-5.13': {
        'focal': {
            '~': '5.13.0-27.29~20.04.1',  # initial publication
        },
    },
    'linux-hwe-5.15': {
        'focal': {
            '~': '5.15.0-41.44~20.04.1',  # initial publication
        },
    },
    'linux-hwe-5.19': {
        'jammy': {
            '~': '5.19.0-28.29~22.04.1',  # initial publication
        },
    },
}


def lookup_glitch_version(src, release, version):
    glitch_version = None
    if src in kernel_glitches and release in kernel_glitches[src]:
        test_version = version
        while test_version in kernel_glitches[src][release]:
            test_version = kernel_glitches[src][release][test_version]
        if test_version != version:
            glitch_version = test_version

    return glitch_version


# list of kernel meta abi versions to ignore abi mismatches when
# published in the archive.
kernel_mabi_glitches = {
    'linux-meta': {
        'bionic': [
            '4.15.0.23.25',  # -24 got reverted due to LP: #1780227
        ],
    },
    'linux-meta-aws': {
        'bionic': [
            '4.15.0.1010.10',  # -1011 got reverted due to LP: #1780227
        ],
    },
    'linux-meta-aws-hwe': {
        'xenial': [
            '4.15.0.1085.81',  # -1008 got reverted due to LP: #1907262
        ],
    },
    'linux-meta-azure': {
        'trusty/esm': [
            '4.15.0.1122.95',  # 4.15.0-1123.136~14.04.1 got reverted
        ],
        'xenial': [
            '4.15.0.1013.20',  # -1014 got reverted due to LP: #1780227
            '4.15.0.1055.58',  # -1055 got reverted
            '4.15.0.1098.92',  # -1100 got reverted due to LP: #1907262
        ],
        'esm-infra/xenial': [
            '4.15.0.1122.113',  # 4.15.0-1123.136~16.04.1 got reverted
        ],
        'bionic': [
            '4.15.0.1013.13',  # -1014 got reverted due to LP: #1780227
            '5.0.0.1028.39',  # -1029 got reverted due to SGX blacklisting
            '5.0.0.1035.46',  # -1036 got accidentally reverted
        ],
        'focal': [
            '5.4.0.1056.54',  # 5.4.0-1058.60 got reverted
        ],
        'hirsute': [
            '5.11.0.1013.14',  # 5.11.0-1015.16 got reverted
        ],
    },
    'linux-meta-azure-4.15': {
        'bionic': [
            '4.15.0.1122.95',  # 4.15.0-1123.136 got reverted
        ],
    },
    'linux-meta-azure-5.4': {
        'bionic': [
            '5.4.0.1056.36',  # 5.4.0-1058.60~18.04.1 got reverted
        ],
    },
    'linux-meta-gcp': {
        'xenial': [
            '4.15.0.1087.88',  # -1088 got reverted due to LP: #1907262
        ],
        'bionic': [
            '4.15.0.1009.11',  # -1010 got reverted due to LP: #1780227
        ],
    },
    'linux-meta-gcp-5.4': {
        'bionic': [
            '5.4.0.1058.44',  # 5.4.0-1059.63~18.04.1 got reverted for unknown reasons
        ],
    },
    'linux-meta-gkeop-5.4': {
        'bionic': [
            '5.4.0.1027.28~18.04.28',  # 5.4.0-1059.63~18.04.1 got reverted for unknown reasons
        ],
    },
    'linux-meta-hwe': {
        'xenial': [
            '4.13.0.45.64',  # 4.15.0-24.26~16.04.1 got reverted due to LP: #1780227
            '4.15.0.123.123',  # -126 got reverted due to LP: #1907262
        ],
    },
    'linux-meta-lts-xenial': {
        'trusty': [
            '4.4.0.142.122',  # -143 got reverted due to bad dependency
        ]
    },
    'linux-meta-kvm': {
        'bionic': [
            '4.15.0.1011.11',  # -1012 got reverted due to LP: #1780227
        ],
    },
    'linux-meta-oem-5.14': {
        'focal': [
            '5.14.0.1050.46',  # not sure why -1051 did not get published to focal-security
        ],
    },
    'linux-meta-oracle': {
        'xenial': [
            '4.15.0.1058.47',  # -1059 got reverted due to LP: #1907262
        ],
    },
}

# for a period of time, there won't be a current linux-hwe-edge or
# linux-azure-edge kernel, and the meta package will point to the
# linux-hwe or linux-azure kernels. Use this exception list to check the
# alternate kernel abi.
kernel_mabi_alt_pkg = {
    'linux-meta-azure-edge': 'linux-azure',
    'linux-meta-hwe-edge': 'linux-hwe',
}

def ignore_kernel_mabi(src, meta_src, release, version):
    return (meta_kernels.ignore_mabi(release, src) or
            (meta_src in kernel_mabi_glitches and
             release in kernel_mabi_glitches[meta_src] and
             version in kernel_mabi_glitches[meta_src][release]))

def get_kernel_meta_alt_pkg(meta_src):
    return kernel_mabi_alt_pkg.get(meta_src)


# return the kernel abi from a kernel version
# e.g. 4.15.0-45.54 => 45
def kernel_package_abi(version):
    return int(version.split('-').pop().split('.', 1)[0])


# return the upstream kernel version from a kernel package version
# e.g. 4.15.0-45.54 => 4.15.0
def kernel_package_version(version):
    return version.split('-')[0]


# return the kernel abi from a kernel meta-package version
# e.g. 4.15.0.45.57 => 45
# XXX may need to add an offset exception to the kernel table
def kernel_meta_abi(version, offset=3):
    return int(version.split('.').pop(offset))
