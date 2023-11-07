#!/usr/bin/env pytest-3
# -*- coding: utf-8 -*-
#
# Author: Steve Beattie <sbeattie@ubuntu.com>
# Copyright (C) 2020 Canonical Ltd.
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.
#
# Simple tests for usn_lib

import pytest
from usn_lib import (
    parse_archive_url
)


class TestParseArchiveUrl:
    def test_basic_url(self):
        url = "http://security.ubuntu.com/ubuntu/pool/main/l/linux-hwe/block-modules-4.18.0-14-generic-di_4.18.0-14.15~18.04.1_amd64.udeb"
        assert parse_archive_url(url) == ("main", "linux-hwe", "block-modules-4.18.0-14-generic-di", "4.18.0-14.15~18.04.1", 'amd64')

    def test_ports_url(self):
        url = "þtp://ports.ubuntu.com/pool/main/l/linux-hwe/linux-image-4.18.0-14-generic_4.18.0-14.15~18.04.1_armhf.deb"
        assert parse_archive_url(url) == ("main", "linux-hwe", "linux-image-4.18.0-14-generic", "4.18.0-14.15~18.04.1", 'armhf')

    def test_bad_security_url(self):
        assert parse_archive_url("http://security.ubuntu.com/ubuntu/pool/") == None

    def test_bad_ports_url(self):
        assert parse_archive_url("http://ports.ubuntu.com/pool/") == None
