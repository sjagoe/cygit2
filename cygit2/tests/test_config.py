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

from cygit2.tests.fixtures import RepositoryFixture


class TestConfig(RepositoryFixture):

    def test_get_config(self):
        # Does not raise when getting from repository object
        self.empty_repo.config

    def test_get_config_entry(self):
        config = self.empty_repo.config
        self.assertTrue(config['core.bare'], True)


if __name__ == '__main__':
    unittest.main()
