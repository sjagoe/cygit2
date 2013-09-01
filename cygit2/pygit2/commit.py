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
from .oid import Oid


class Commit(Object):

    def read_raw(self):
        return self._object.read_raw()

    def ancestor(self, generation):
        return Commmit(self._object.ancestor(generation))

    @property
    def message_encoding(self):
        return self._object.message_encoding

    @property
    def message(self):
        return self._object.message

    @property
    def _message(self):
        return self._object._message

    @property
    def commit_time(self):
        return self._object.commit_time

    @property
    def time_offset(self):
        return self._object.time_offset

    @property
    def committer(self):
        return self._object.committer

    @property
    def author(self):
        return self._object.author

    @property
    def tree(self):
        return self.convert(self._object.tree)

    @property
    def tree_id(self):
        return Oid(self._object.tree_id)

    @property
    def parents(self):
        return [Commit(p) for p in self._object.parents]

    @property
    def parent_ids(self):
        return [Oid(i) for i in self._object.parent_ids]
