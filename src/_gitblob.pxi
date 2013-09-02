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

from _blob cimport (
    git_blob_free,
    git_blob_id,
    git_blob_rawcontent,
    git_blob_rawsize,
)


cdef class GitBlob(GitObject):

    def __dealloc__(GitBlob self):
        if self._object is not NULL:
            git_blob_free(<git_blob*>self._object)

    cpdef read_raw(GitBlob self):
        cdef bytes py_content
        cdef char *content = <char*>git_blob_rawcontent(<git_blob*>self._object)
        py_content = content
        return py_content

    property oid:
        def __get__(GitBlob self):
            cdef const_git_oid *oidp
            oidp = git_blob_id(<git_blob*>self._object)
            return make_oid(self, oidp)

    property data:
        def __get__(GitBlob self):
            return self.read_raw()

    property size:
        def __get__(GitBlob self):
            cdef git_off_t size = git_blob_rawsize(<git_blob*>self._object)
            return int(size)
