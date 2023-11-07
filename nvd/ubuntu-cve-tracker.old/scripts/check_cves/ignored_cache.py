#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  Copyright (C) 2022 Canonical Ltd.
#
#  Implements a simple cache for recent reasons for ignoring CVE
#  entries, as used by check-cves


class IgnoredCache():
    # Keeps a list of ignored entries with a maximum length

    _ignored = list()

    def __init__(self, initial_list=None, max_len=5):
        if initial_list:
            self._ignored = initial_list
        self.max_len = max_len
        self._prune_cache()

    # ensure list is less than or equal to the maximum length, and prune
    # if not
    def _prune_cache(self):
        if len(self._ignored) > self.max_len:
            self._ignored = self._ignored[:self.max_len]

    def insert(self, reason):
        # if the reason already exists, remove it so it can be
        # reinserted at the head of the list
        if reason in self._ignored:
            self._ignored.remove(reason)

        self._ignored.insert(0, reason)
        self._prune_cache()

    def get(self):
        return self._ignored
