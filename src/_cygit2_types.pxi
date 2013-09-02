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
import cython


from _types cimport (
    GIT_OBJ_ANY,
    GIT_OBJ_BAD,
    GIT_OBJ_BLOB,
    GIT_OBJ_COMMIT,
    GIT_OBJ_OFS_DELTA,
    GIT_OBJ_REF_DELTA,
    GIT_OBJ_TAG,
    GIT_OBJ_TREE,
    GIT_OBJ__EXT1,
    GIT_OBJ__EXT2,
    GIT_REF_INVALID,
    GIT_REF_LISTALL,
    GIT_REF_OID,
    GIT_REF_SYMBOLIC,
)


@cython.internal
cdef class _GitReferenceType:

    cdef readonly EnumValue INVALID
    cdef readonly EnumValue OID
    cdef readonly EnumValue SYMBOLIC
    cdef readonly EnumValue LISTALL

    def __init__(_GitReferenceType self):
        self.INVALID  = EnumValue('GitReferenceType.INVALID', GIT_REF_INVALID)
        self.OID      = EnumValue('GitReferenceType.OID', GIT_REF_OID)
        self.SYMBOLIC = EnumValue('GitReferenceType.SYMBOLIC', GIT_REF_SYMBOLIC)
        self.LISTALL  = EnumValue('GitReferenceType.LISTALL', GIT_REF_LISTALL)

    cdef EnumValue _from_git_ref_t(_GitReferenceType self, git_ref_t type_):
        for item in (self.INVALID,
                     self.OID,
                     self.SYMBOLIC,
                     self.LISTALL):
            if type_ == item.value:
                return item
        raise LibGit2Error('Invalid GitReferenceType: {!r}'.format(type_))

    cdef _to_git_ref_t(_GitReferenceType self, EnumValue type_):
        for item in (self.INVALID,
                     self.OID,
                     self.SYMBOLIC,
                     self.LISTALL):
            if type_ == item:
                return item.value
        raise LibGit2Error('Invalid GitReferenceType: {!r}'.format(type_))


GitReferenceType = _GitReferenceType()


@cython.internal
cdef class _GitObjectType:

    cdef readonly EnumValue ANY
    cdef readonly EnumValue BAD
    cdef readonly EnumValue _EXT1
    cdef readonly EnumValue COMMIT
    cdef readonly EnumValue TREE
    cdef readonly EnumValue BLOB
    cdef readonly EnumValue TAG
    cdef readonly EnumValue _EXT2
    cdef readonly EnumValue OFS_DELTA
    cdef readonly EnumValue REF_DELTA

    def __init__(_GitObjectType self):
        self.ANY       = EnumValue('GitObjectType.ANY', GIT_OBJ_ANY)
        self.BAD       = EnumValue('GitObjectType.BAD', GIT_OBJ_BAD)
        self._EXT1     = EnumValue('GitObjectType._EXT1', GIT_OBJ__EXT1)
        self.COMMIT    = EnumValue('GitObjectType.COMMIT', GIT_OBJ_COMMIT)
        self.TREE      = EnumValue('GitObjectType.TREE', GIT_OBJ_TREE)
        self.BLOB      = EnumValue('GitObjectType.BLOB', GIT_OBJ_BLOB)
        self.TAG       = EnumValue('GitObjectType.TAG', GIT_OBJ_TAG)
        self._EXT2     = EnumValue('GitObjectType._EXT2', GIT_OBJ__EXT2)
        self.OFS_DELTA = EnumValue('GitObjectType.OFS_DELTA', GIT_OBJ_OFS_DELTA)
        self.REF_DELTA = EnumValue('GitObjectType.REF_DELTA', GIT_OBJ_REF_DELTA)

    cdef EnumValue _from_uint(_GitObjectType self, unsigned int type_):
        for item in (self.ANY,
                     self.BAD,
                     self._EXT1,
                     self.COMMIT,
                     self.TREE,
                     self.BLOB,
                     self.TAG,
                     self._EXT2,
                     self.OFS_DELTA,
                     self.REF_DELTA):
            if type_ == item.value:
                return item
        raise LibGit2Error('Invalid GitObjectType: {!r}'.format(type_))

    cdef _to_uint(_GitObjectType self, EnumValue type_):
        for item in (self.ANY,
                     self.BAD,
                     self._EXT1,
                     self.COMMIT,
                     self.TREE,
                     self.BLOB,
                     self.TAG,
                     self._EXT2,
                     self.OFS_DELTA,
                     self.REF_DELTA):
            if type_ == item:
                return item.value
        raise LibGit2Error('Invalid GitObjectType: {!r}'.format(type_))


GitObjectType = _GitObjectType()
