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

from _types cimport git_object
from _object cimport (
    git_object_free,
    git_object_type,
)


cdef _GitObject_from_git_object_pointer(Repository repo, git_object *_object):
    cdef _GitObjectType ObjType = GitObjectType
    if _object is NULL:
        return None

    cdef unsigned int t = <unsigned int>git_object_type(_object)
    type_ = ObjType._from_uint(<unsigned int>t)
    if type_ == ObjType.COMMIT:
        commit = GitCommit(repo)
        commit._object = _object
        return commit
    elif type_ == ObjType.TREE:
        tree = GitTree(repo)
        tree._object = _object
        return tree
    elif type_ == ObjType.BLOB:
        blob = GitBlob(repo)
        blob._object = _object
        return blob
    git_object_free(_object)
    raise TypeError('Unsupported object type {!r}'.format(type_))


cdef class GitObject:

    cdef git_object *_object

    cdef Repository _repository

    def __cinit__(GitObject self):
        self._object = NULL

    def __init__(self, Repository repo):
        self._repository = repo

    property type:
        def __get__(GitCommit self):
            cdef _GitObjectType ObjType = GitObjectType
            return ObjType._from_uint(git_object_type(self._object))

    property hex:
        def __get__(GitCommit self):
            return self.oid.hex
