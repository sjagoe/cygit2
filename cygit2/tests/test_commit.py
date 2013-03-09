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

from cygit2.tests.fixtures import Cygit2RepositoryFixture


class TestCommit(Cygit2RepositoryFixture):

    def setUp(self):
        super(TestCommit, self).setUp()
        ref = self.repo.lookup_ref('refs/heads/master')
        self.commit = self.repo.lookup_commit(ref.oid)

    def tearDown(self):
        del self.commit
        super(TestCommit, self).tearDown()

    def test_get_committer(self):
        committer = self.commit.committer
        self.assertEqual(committer.name, 'Test User')
        self.assertEqual(committer.email, 'test@users.invalid')

    def test_get_author(self):
        author = self.commit.author
        self.assertEqual(author.name, 'Other User')
        self.assertEqual(author.email, 'other@users.invalid')


if __name__ == '__main__':
    unittest.main()
