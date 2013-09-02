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

from _reflog cimport (
    git_reflog_free,
    git_reflog_read,
    git_reflog_entrycount,
    git_reflog_entry_byindex,
    git_reflog_entry_id_new,
    git_reflog_entry_id_old,
    git_reflog_entry_message,
)

from _refs cimport (
    git_reference_free,
    git_reference_lookup,
    git_reference_name,
    git_reference_target,
    git_reference_cmp,
    git_reference_has_log,
    git_reference_list,
    git_reference_is_valid_name,
    git_reference_is_branch,
    git_reference_is_remote,
    git_reference_type,
    git_reference_symbolic_target,
    git_reference_resolve,
)


cdef class RefLogEntry:

    cdef const_git_reflog_entry *_entry

    cdef object _reference

    def __cinit__(RefLogEntry self):
        self._entry = NULL

    def __init__(RefLogEntry self, reference):
        self._reference = reference

    property id_new:
        def __get__(RefLogEntry self):
            cdef const_git_oid *oidp
            oidp = git_reflog_entry_id_new(self._entry)
            return make_oid(self, oidp)

    property id_old:
        def __get__(RefLogEntry self):
            cdef const_git_oid *oidp
            oidp = git_reflog_entry_id_old(self._entry)
            return make_oid(self, oidp)

    property message:
        def __get__(RefLogEntry self):
            cdef char *message
            message = <char*>git_reflog_entry_message(self._entry)
            return message.decode(DEFAULT_ENCODING)


cdef class Reference:

    cdef git_reference *_reference

    def __cinit__(Reference self):
        self._reference = NULL

    def __dealloc__(Reference self):
        if self._reference is not NULL:
            git_reference_free(self._reference)

    def __richcmp__(Reference self, Reference other, int op):
        cdef int cmp_ = git_reference_cmp(self._reference, other._reference)
        if op == 2: # ==
            return cmp_ == 0
        elif op == 3: # !=
            return cmp_ != 0
        elif op == 0: # <
            return cmp_ < 0
        elif op == 1: # <=
            return cmp_ <= 0
        elif op == 4: # >
            return cmp_ > 0
        elif op == 5: # >=
            return cmp_ >= 0

    def has_log(Reference self):
        cdef int code
        code = git_reference_has_log(self._reference)
        if code == 0:
            return False
        elif code == 1:
            return True
        else:
            check_error(code)

    def logs(Reference self):
        cdef int i
        cdef int size
        cdef int error
        cdef git_reflog *reflog
        error = git_reflog_read(cython.address(reflog), self._reference)
        check_error(error)
        i = 0
        size = git_reflog_entrycount(reflog)
        try:
            while i < size:
                entry = RefLogEntry(self)
                entry._entry = git_reflog_entry_byindex(reflog, i)
                i += 1
                yield entry
        finally:
            git_reflog_free(reflog)

    def is_branch(Reference self):
        return git_reference_is_branch(self._reference) != 0

    def is_remote(Reference self):
        return git_reference_is_remote(self._reference) != 0

    cdef git_ref_t _type(Reference self):
        return git_reference_type(self._reference)

    def resolve(Reference self):
        cdef int error
        cdef git_ref_t type_ = self._type()
        if type_ == GIT_REF_OID:
            return self
        if type_ == GIT_REF_SYMBOLIC:
            ref = Reference()
            error = git_reference_resolve(cython.address(ref._reference),
                                          self._reference)
            check_error(error)
            return ref

    property name:
        def __get__(Reference self):
            cdef bytes py_string = git_reference_name(self._reference)
            return py_string.decode(DEFAULT_ENCODING)

    property target:
        def __get__(Reference self):
            cdef const_git_oid *oidp
            cdef bytes py_string
            cdef git_ref_t type_ = git_reference_type(self._reference)
            if type_ == GIT_REF_OID:
                oidp = git_reference_target(self._reference)
                return make_oid(self, oidp)
            elif type_ == GIT_REF_SYMBOLIC:
                py_string = git_reference_symbolic_target(
                    self._reference)
                return py_string.decode(DEFAULT_ENCODING)

    property oid:
        def __get__(Reference self):
            cdef const_git_oid *oidp
            oidp = git_reference_target(self._reference)
            return make_oid(self, oidp)

    property hex:
        def __get__(Reference self):
            return self.oid.hex

    property type:
        def __get__(Reference self):
            cdef _GitReferenceType RefType = GitReferenceType
            cdef git_ref_t type_ = self._type()
            return RefType._from_git_ref_t(type_)
