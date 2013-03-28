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

import unittest

from cygit2._cygit2 import LibGit2ReferenceError

from cygit2.tests.fixtures import RepositoryFixture, Cygit2RepositoryFixture


class TestReferenceEmptyRepository(RepositoryFixture):

    def setUp(self):
        super(TestReferenceEmptyRepository, self).setUp()
        self.ref = self.empty_repo.lookup_reference('HEAD')

    def tearDown(self):
        del self.ref
        super(TestReferenceEmptyRepository, self).tearDown()

    def test_get_invalid_reference(self):
        with self.assertRaises(LibGit2ReferenceError):
            ref = self.empty_repo.lookup_reference('invalid')

    def test_cmp(self):
        # Test that __cmp__ returns 0 for two equal refs.  The two
        # objects here should have different IDs (i.e. are different
        # instances)
        ref2 = self.empty_repo.lookup_reference('HEAD')
        self.assertEqual(self.ref, ref2)
        self.assertNotEqual(id(self.ref), id(ref2))

    def test_name_property(self):
        self.assertEqual(self.ref.name, 'HEAD')

    def test_has_log(self):
        self.assertFalse(self.ref.has_log())

    def test_is_branch_empty_repo(self):
        self.assertFalse(self.ref.is_branch())

    def test_is_remote_empty_repo(self):
        self.assertFalse(self.ref.is_remote())

    def test_oid_property_no_ref(self):
        oid = self.ref.oid
        self.assertIsNone(oid)


class TestReference(Cygit2RepositoryFixture):

    def test_oid_property(self):
        ref = self.repo.lookup_reference('refs/heads/master')
        oid = ref.oid

    def test_reflog(self):
        ref = self.repo.lookup_reference('refs/heads/master')
        self.assertGreater(len(list(ref.logs())), 0)


if __name__ == '__main__':
    unittest.main()
