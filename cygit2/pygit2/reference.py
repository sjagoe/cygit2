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

from .object import Object


class Reference(object):

    def __init__(self, reference):
        self._reference = reference

    def __eq__(self, other):
        return self._reference == other._reference

    def __ne__(self, other):
        return not (self == other)

    def __gt__(self, other):
        return self._reference > other._reference

    def __ge__(self, other):
        return not (self < other)

    def __lt__(self, other):
        return self._reference < other._reference

    def __le__(self, other):
        return not (self > other)

    def get_object(self):
        return Object.convert(self._reference.get_object())

    def has_log(self):
        return self._reference.has_log()

    def logs(self):
        for entry in self._reference.logs():
            yield entry

    def is_branch(self):
        return self._reference.is_branch()

    def is_remote(self):
        return self._reference.is_remote()

    def resolve(self):
        ref = self._reference.resolve()
        if ref is self._reference:
            return self
        return Reference(ref)

    @property
    def name(self):
        return self._reference.name

    @property
    def target(self):
        return self._reference.target

    @property
    def oid(self):
        return self._reference.oid

    @property
    def hex(self):
        return self._reference.hex

    @property
    def type(self):
        return self._reference.type
