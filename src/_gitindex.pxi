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

from _types cimport (
    git_index,
)

from _index cimport (
    git_index_entry,
    git_index_entrycount,
    git_index_find,
    git_index_free,
    git_index_get_byindex,
    git_index_get_bypath,
)


cdef class GitIndexEntry:

    cdef const git_index_entry *_entry

    cdef object _owner

    def __cinit__(self):
        self._entry = NULL
        self._owner = None

    def __dealloc__(self):
        self._owner = None
        self._entry = NULL


cdef class GitIndex:

    cdef git_index *_index

    def __cinit__(self):
        self._index = NULL

    def __dealloc__(self):
        if self._index is not NULL:
            git_index_free(self._index)
            self._index = NULL

    def __len__(self):
        cdef size_t count = git_index_entrycount(self._index)
        return count

    def __getitem__(self, value):
        cdef bytes bpath
        cdef char *c_path
        cdef long index
        cdef const git_index_entry *index_entry = NULL
        if isinstance(value, unicode) or isinstance(value, bytes):
            if isinstance(value, unicode):
                path = value.encode(DEFAULT_ENCODING)
            else:
                path = value
            c_path = path
            index_entry = git_index_get_bypath(self._index, c_path, 0)
        else:
            index = value
            if index < 0:
                raise ValueError(value)
            index_entry = git_index_get_byindex(self._index, index)
        if index_entry is NULL:
            raise KeyError(value)
        cdef GitIndexEntry entry = GitIndexEntry.__new__(GitIndexEntry)
        entry._entry = index_entry
        entry._owner = self
        return entry

    def __contains__(self, value):
        cdef int error
        cdef bytes bpath
        cdef char *c_path
        if isinstance(value, unicode) or isinstance(value, bytes):
            if isinstance(value, unicode):
                path = value.encode(DEFAULT_ENCODING)
            else:
                path = value
            c_path = path
            error = git_index_find(NULL, self._index, c_path)
            if error == GIT_ENOTFOUND:
                return False
            check_error(error)
            return True
        raise TypeError(value)
