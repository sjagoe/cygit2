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

from _types cimport git_odb

from _odb cimport (
    git_odb_read_prefix,
    git_odb_free,
    git_odb_foreach,
    git_odb_object,
    git_odb_object_free,
    git_odb_object_id,
    git_odb_object_data,
    git_odb_object_size,
    git_odb_object_type,
)


cdef class GitOdbObject:

    cdef git_odb_object *_object

    def __cinit__(GitOdbObject self):
        self._object = NULL

    def __dealloc__(GitOdbObject self):
        if self._object is not NULL:
            git_odb_object_free(self._object)

    cdef _compare_type_contents(GitOdbObject self,
                                EnumValue other_type, other_contents,
                                int op):
        if op == 2: # ==
            return self.type == other_type and self.data == other_contents
        elif op == 3: # !=
            return not (self.type == other_type and self.data == other_contents)
        elif op == 0: # <
            return self.type < other_type and self.data < other_contents
        elif op == 1: # <= (not >)
            return not (self.type > other_type and self.data > other_contents)
        elif op == 4: # >
            return self.type > other_type and self.data > other_contents
        elif op == 5: # >= (not <)
            return not (self.type < other_type and self.data < other_contents)

    def __richcmp__(GitOdbObject self, other, int op):
        cdef bytes other_contents
        cdef EnumValue other_type
        if isinstance(other, tuple):
            other_type = other[0]
            if isinstance(other[1], unicode):
                other_contents = other[1].encode(DEFAULT_ENCODING)
            else:
                other_contents = other[1]
            return self._compare_type_contents(other_type, other_contents, op)
        if not isinstance(other, GitOdbObject):
            return False
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
        def __get__(GitOdbObject self):
            cdef const_git_oid *oidp
            oidp = git_odb_object_id(self._object)
            return make_oid(self, oidp)

    property data:
        def __get__(GitOdbObject self):
            cdef const_char *string = <const_char*>git_odb_object_data(self._object)
            cdef bytes data = <char*>string
            return data

    property size:
        def __get__(GitOdbObject self):
            cdef size_t size = git_odb_object_size(self._object)
            return size

    property type:
        def __get__(GitOdbObject self):
            cdef _GitObjectType ObjType = GitObjectType
            cdef unsigned int utype = git_odb_object_type(self._object)
            return ObjType._from_uint(utype)

    def __repr__(GitOdbObject self):
        return '<GitOdbObject type={!r} size={!r}>'.format(self.type, self.size)


cdef int _GitOdb_get_oids(const_git_oid *oid, void *payload):
    cdef tuple py_payload = <object>payload
    owner, result = py_payload
    result.append(make_oid(owner, oid))
    return 0


@cython.internal
cdef class GitOdb:

    cdef git_odb *_odb

    def __cinit__(GitOdb self):
        self._odb = NULL

    def __dealloc__(GitOdb self):
        if self._odb is not NULL:
            git_odb_free(self._odb)

    cdef GitOdbObject read_prefix(GitOdb self, GitOid oid):
        cdef int error
        cdef GitOdbObject obj = GitOdbObject()
        assert_GitOid(oid)
        error = git_odb_read_prefix(cython.address(obj._object), self._odb,
                                    oid._oid, oid.length)
        check_error(error)
        return obj

    cdef oids(GitOdb self):
        cdef int error
        cdef object payload = (self, [])
        error = git_odb_foreach(self._odb, _GitOdb_get_oids, <void*>payload)
        return payload[1]
