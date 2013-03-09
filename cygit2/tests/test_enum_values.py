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

from cygit2._cygit2 import GitStatus

class TestEnumValue(unittest.TestCase):

    def test_composing_enums(self):
        composed1 = GitStatus.INDEX_NEW | GitStatus.INDEX_MODIFIED | GitStatus.WT_NEW
        self.assertGreater(composed1, GitStatus.INDEX_NEW)
        self.assertGreater(composed1, GitStatus.INDEX_MODIFIED)
        self.assertGreater(composed1, GitStatus.WT_NEW)

        composed2 = (GitStatus.INDEX_NEW | GitStatus.WT_NEW) | GitStatus.WT_MODIFIED
        self.assertGreater(composed2, GitStatus.INDEX_NEW)
        self.assertGreater(composed2, GitStatus.WT_NEW)
        self.assertGreater(composed2, GitStatus.WT_MODIFIED)

        composed3 = GitStatus.WT_MODIFIED | (GitStatus.INDEX_NEW | GitStatus.WT_NEW)
        self.assertEqual(composed3, composed2)

        composed4 = (GitStatus.INDEX_NEW | GitStatus.WT_NEW) & GitStatus.WT_MODIFIED
        self.assertEqual(composed4.value, 0)

        composed5 = GitStatus.WT_MODIFIED & (GitStatus.INDEX_NEW | GitStatus.WT_NEW)
        self.assertEqual(composed5, composed4)

        composed6 = (GitStatus.INDEX_NEW | GitStatus.WT_NEW) & GitStatus.WT_NEW
        self.assertEqual(composed6, GitStatus.WT_NEW)

        composed7 = GitStatus.WT_NEW & (GitStatus.INDEX_NEW | GitStatus.WT_NEW)
        self.assertEqual(composed7, GitStatus.WT_NEW)


if __name__ == '__main__':
    unittest.main()
