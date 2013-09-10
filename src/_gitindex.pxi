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


@cython.internal
cdef class GitIndexEntry:

    cdef const git_index_entry *_entry

    cdef object _owner

    def __cinit__(GitIndexEntry self):
        self._entry = NULL
        self._owner = None

    def __dealloc__(GitIndexEntry self):
        self._owner = None
        self._entry = NULL

    property oid:
        def __get__(GitIndexEntry self):
            cdef const_git_oid *oidp = cython.address(self._entry.oid)
            return make_oid(self, oidp)

    property hex:
        def __get__(GitIndexEntry self):
            return self.oid.hex

    property path:
        def __get__(GitIndexEntry self):
            cdef bytes path = self._entry.path
            return path.decode(DEFAULT_ENCODING)

    property mode:
        def __get__(GitIndexEntry self):
            return self._entry.mode


@cython.internal
cdef class GitIndexIter:

    cdef GitIndex _owner

    cdef long _index

    def __cinit__(GitIndexIter self):
        self._index = 0
        self._owner = None

    def __dealloc__(GitIndexIter self):
        self._owner = None
        self._index = 0

    def __next__(GitIndexIter self):
        cdef const git_index_entry *index_entry = NULL
        index_entry = git_index_get_byindex(self._owner._index, self._index)
        if index_entry is NULL:
            raise StopIteration()
        self._index += 1

        cdef GitIndexEntry entry = GitIndexEntry.__new__(GitIndexEntry)
        entry._entry = index_entry
        entry._owner = self._owner
        return entry


cdef class GitIndex:

    cdef git_index *_index

    def __cinit__(GitIndex self):
        self._index = NULL

    def __dealloc__(GitIndex self):
        if self._index is not NULL:
            git_index_free(self._index)
            self._index = NULL

    def __len__(GitIndex self):
        cdef size_t count = git_index_entrycount(self._index)
        return count

    def __getitem__(GitIndex self, value):
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

    def __contains__(GitIndex self, value):
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

    def __iter__(GitIndex self):
        cdef GitIndexIter iter = GitIndexIter.__new__(GitIndexIter)
        iter._owner = self
        return iter
