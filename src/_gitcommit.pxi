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

from _types cimport git_commit
from _commit cimport (
    git_commit_author,
    git_commit_committer,
    git_commit_free,
    git_commit_id,
    git_commit_message,
    git_commit_message_encoding,
    git_commit_nth_gen_ancestor,
    git_commit_parent,
    git_commit_parent_id,
    git_commit_parentcount,
    git_commit_time,
    git_commit_time_offset,
    git_commit_tree,
    git_commit_tree_id,
)


cdef class GitCommit(GitObject):

    def __dealloc__(GitCommit self):
        if self._object is not NULL:
            git_commit_free(<git_commit*>self._object)

    cdef object _get_message(GitCommit self):
        cdef bytes py_string
        cdef const_char *message = git_commit_message(<git_commit*>self._object)
        if message is NULL:
            return None
        py_string = <char*>message
        return py_string

    def ancestor(GitCommit self, unsigned int generation):
        cdef int error
        cdef GitCommit parent = GitCommit()
        error = git_commit_nth_gen_ancestor(<git_commit**>cython.address(parent._object),
                                            <git_commit*>self._object, generation)
        check_error(error)
        return parent

    def __richcmp__(GitCommit self, GitCommit other not None, int op):
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
        def __get__(GitCommit self):
            cdef const_git_oid *oidp
            oidp = git_commit_id(<git_commit*>self._object)
            return make_oid(self, oidp)

    property message_encoding:
        def __get__(GitCommit self):
            cdef bytes py_string
            cdef const_char *encoding = git_commit_message_encoding(<git_commit*>self._object)
            if encoding is NULL:
                return None
            py_string = <char*>encoding
            return py_string.decode('ascii') # Will it always be ascii?

    property message:
        def __get__(GitCommit self):
            message = self._get_message()
            if message is None:
                return None
            encoding = self.message_encoding
            if encoding is None:
                encoding = DEFAULT_ENCODING
            return message.decode(encoding)

    property _message:
        def __get__(GitCommit self):
            return self._get_message()

    # FIXME: Convert time and time_offset into datetime
    property commit_time:
        def __get__(GitCommit self):
            cdef git_time_t time = git_commit_time(<git_commit*>self._object)
            cdef object py_time = time
            return py_time

    property time_offset:
        def __get__(GitCommit self):
            cdef int offset = git_commit_time_offset(<git_commit*>self._object)
            return offset

    property committer:
        def __get__(GitCommit self):
            cdef const_git_signature *sig = git_commit_committer(<git_commit*>self._object)
            return _make_signature(sig, self)

    property author:
        def __get__(GitCommit self):
            cdef const_git_signature *sig = git_commit_author(<git_commit*>self._object)
            return _make_signature(sig, self)

    property tree:
        def __get__(GitCommit self):
            cdef int error
            cdef GitTree tree = GitTree(self._repository)
            error = git_commit_tree(<git_tree**>cython.address(tree._object),
                                    <git_commit*>self._object)
            check_error(error)
            return tree

    property tree_id:
        def __get__(GitCommit self):
            cdef const_git_oid *oidp
            oidp = git_commit_tree_id(<git_commit*>self._object)
            return make_oid(self, oidp)

    property parents:
        def __get__(GitCommit self):
            cdef int error
            cdef int count
            cdef int index
            cdef GitCommit parent
            count = git_commit_parentcount(<git_commit*>self._object)
            if count == 0:
                return []
            parents = []
            for index from 0 <= index < count:
                parent = GitCommit(self._repository)
                error = git_commit_parent(<git_commit**>cython.address(parent._object),
                                          <git_commit*>self._object, index)
                check_error(error)
                parents.append(parent)
            return parents

    property parent_ids:
        def __get__(GitCommit self):
            cdef int error
            cdef int count
            cdef int index
            cdef const_git_oid *oidp
            cdef GitOid oid
            count = git_commit_parentcount(<git_commit*>self._object)
            if count == 0:
                return []
            parent_ids = []
            for index from 0 <= index < count:
                oidp = git_commit_parent_id(<git_commit*>self._object, index)
                oid = make_oid(self, oidp)
                if oid is not None:
                    parent_ids.append(oid)
            return parent_ids
