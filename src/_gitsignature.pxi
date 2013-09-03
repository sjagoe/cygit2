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
from _types cimport git_signature, const_git_signature
from _signature cimport (
    git_signature_free,
    git_signature_new,
    git_signature_now,
)


cdef class GitSignature:

    cdef git_signature *_signature

    cdef object _owner

    cdef readonly unicode _encoding

    def __cinit__(GitSignature self):
        self._signature = NULL
        self._owner = None

    def __init__(GitSignature self, name=None, email=None, time=None,
                 offset=None, encoding=None):
        cdef int error
        cdef bytes bytes_name
        cdef bytes bemail
        cdef char *c_name = NULL
        cdef char *c_email = NULL
        cdef git_time_t c_time = -1
        cdef int c_offset = 0

        if name is None or email is None:
            self._encoding = DEFAULT_ENCODING
            return # Fixme

        if encoding is not None:
            encoding = encoding[:len(encoding)]
        else:
            encoding = u'ascii'

        if name is not None:
            bytes_name = _to_bytes(name, encoding)
            c_name = bytes_name
        if email is not None:
            bemail = _to_bytes(email, encoding)
            c_email = bemail
        if time is not None:
            c_time = time
        if offset is not None:
            c_offset = offset

        if c_time != -1:
            error = git_signature_new(cython.address(self._signature), c_name,
                                      c_email, c_time, c_offset)
        else:
            error = git_signature_now(cython.address(self._signature), c_name,
                                      c_email)
        check_error(error)

        self._encoding = encoding

    def __dealloc__(GitSignature self):
        if self._signature is not NULL and self._owner is None:
            git_signature_free(self._signature)

    property _name:
        def __get__(GitSignature self):
            cdef bytes py_string = self._signature.name
            return py_string

    property name:
        def __get__(GitSignature self):
            return self._name.decode(self._encoding)

    property email:
        def __get__(GitSignature self):
            cdef bytes py_string = self._signature.email
            return py_string.decode(self._encoding)

    property time:
        def __get__(GitSignature self):
            cdef git_time_t time = self._signature.when.time
            return time

    property offset:
        def __get__(GitSignature self):
            cdef int time = self._signature.when.offset
            return time


cdef GitSignature _make_signature(const_git_signature *_signature, object owner):
    if _signature is NULL:
        return None
    # FIXME: Inefficient
    cdef GitSignature signature = GitSignature()
    # git_signature_free(signature._signature)
    signature._signature = NULL
    signature._owner = owner
    signature._signature = <git_signature*>_signature
    return signature
