# -*- coding: utf-8 -*-
#
# Copyright 2010-2013 The cygit2 contributors
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
from cygit2._cygit2 import (
    LibGit2ConfigError,
    GitRemote,
)


class Remote(object):

    def __init__(self, remote):
        self._remote = remote

    @property
    def name(self):
        return self._remote.name

    @name.setter
    def name(self, value):
        try:
            self._remote.name = value
        except LibGit2ConfigError as e:
            raise ValueError(e)

    @property
    def refspec_count(self):
        return self._remote.refspec_count

    @property
    def url(self):
        return self._remote.url

    @url.setter
    def url(self, value):
        try:
            self._remote.url = value
        except LibGit2ConfigError as e:
            raise ValueError(e)

    def get_refspec(self, number):
        refspec = self._remote.get_refspec(number)
        return (refspec.source, refspec.dest)

    def save(self):
        self._remote.save()
