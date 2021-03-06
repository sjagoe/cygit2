# -*- coding: utf-8 -*-
#
# Copyright 2013 The cygit2 contributors
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2,
# as published by the Free Software Foundation.
#
# In addition to the permissions in the GNU General Public License,
# the authors give you unlimited permission to link the compiled
# version of this file into combinations with other programs,
# and to distribute those combinations without any restriction
# coming from the use of this file.  (The General Public License
# restrictions do apply in other respects; for example, they cover
# modification of the file, and distribution when not linked into
# a combined executable.)
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 51 Franklin Street, Fifth Floor,
# Boston, MA 02110-1301, USA.

from __future__ import unicode_literals

import unittest

from cygit2._cygit2 import GitOid


class TestGitOid(unittest.TestCase):

    def test_oid_short(self):
        oid = GitOid('abc123efab')
        self.assertEqual(oid.hex, 'abc123efab')

    def test_oid_full(self):
        oid = GitOid('abc123efababc123efababc123efababc123efab')
        self.assertEqual(oid.hex, 'abc123efababc123efababc123efababc123efab')


if __name__ == '__main__':
    unittest.main()
