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
    git_tree_entry,
    const_git_tree_entry,
)


from _tree cimport \
    git_tree_free, git_tree_lookup_prefix, git_tree_id, \
    git_tree_entry_bypath, git_tree_entry_byindex, git_tree_entrycount, \
    git_tree_entry_id, git_tree_entry_dup, git_tree_entry_free, \
    git_tree_entry_name, git_tree_entry_byname, git_tree_entry_filemode, \
    git_tree_entry_to_object


cdef class GitTreeEntry:

    cdef git_tree_entry *_entry

    cdef Repository _repository

    def __cinit__(GitTreeEntry self):
        self._entry = NULL

    def __init__(self, Repository repo):
        self._repository = repo

    def __dealloc__(GitTreeEntry self):
        if self._entry is not NULL:
            git_tree_entry_free(self._entry)

    property name:
        def __get__(GitTreeEntry self):
            cdef const_char *path = git_tree_entry_name(self._entry)
            cdef bytes py_path = path
            return py_path.decode(DEFAULT_ENCODING)

    property oid:
        def __get__(GitTreeEntry self):
            cdef const_git_oid *oidp
            oidp = git_tree_entry_id(self._entry)
            return make_oid(self, oidp)

    property hex:
        def __get__(self):
            return self.oid.hex

    property filemode:
        def __get__(self):
            return long(git_tree_entry_filemode(self._entry))

    def to_object(self):
        cdef int error
        cdef git_object *_object
        error = git_tree_entry_to_object(cython.address(_object),
                                         self._repository._repository,
                                         self._entry)
        check_error(error)
        return _GitObject_from_git_object_pointer(self._repository, _object)


cdef class GitTree(GitObject):

    def __dealloc__(GitTree self):
        if self._object is not NULL:
            git_tree_free(<git_tree*>self._object)

    def __richcmp__(GitTree self, GitTree other not None, int op):
        if op == 2: # ==
            return self.oid == other.oid
        elif op == 3: # !=
            return self.oid != other.oid
        elif op == 0: # <
            return self.oid < other.oid
        elif op == 1: # <= (not >)
            return not (self.oid > other.oid)
        elif op == 4: # >
            return self.oid > other.oid
        elif op == 5: # >= (not <)
            return not (self.oid < other.oid)

    property oid:
        def __get__(GitTree self):
            cdef const_git_oid *oidp
            oidp = git_tree_id(<git_tree*>self._object)
            return make_oid(self, oidp)

    cdef size_t _len(GitTree self):
        return git_tree_entrycount(<git_tree*>self._object)

    def __len__(GitTree self):
        len_ = self._len()
        return len_

    cdef _item_by_index(GitTree self, index):
        cdef long index_ = index
        cdef size_t len_ = self._len()
        cdef long llen = <long>len_
        if index_ >= llen:
            raise IndexError(index)
        elif index_ < -llen:
            raise IndexError(index)
        if index_ < 0:
            index_ = len_ + index_

        entry = GitTreeEntry(self._repository)
        entry._entry = git_tree_entry_dup(
            git_tree_entry_byindex(<git_tree*>self._object, index_))
        return entry

    cdef _item_by_path(GitTree self, path):
        cdef int error
        cdef bytes bpath = _to_bytes(path)

        entry = GitTreeEntry(self._repository)
        error = git_tree_entry_bypath(cython.address(entry._entry),
                                      <git_tree*>self._object, bpath)
        if error != GIT_OK:
            raise KeyError(path)
        return entry

    def __getitem__(GitTree self, value):
        if isinstance(value, int) or isinstance(value, long):
            return self._item_by_index(value)
        elif isinstance(value, bytes) or isinstance(value, unicode):
            return self._item_by_path(value)
        else:
            raise TypeError('Unexpected {}'.format(type(value)))

    def __contains__(GitTree self, filename):
        """Returns True if the item specified by ``filename`` is in the tree.

        """
        cdef bytes bpath = _to_bytes(filename)
        cdef const_git_tree_entry *entry = git_tree_entry_byname(
            <git_tree*>self._object, bpath)
        if entry is NULL:
            return False
        return True
