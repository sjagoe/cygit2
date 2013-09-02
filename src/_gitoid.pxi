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

from _oid cimport (
    git_oid_fmt,
    git_oid_fromstrn,
    git_oid_fromraw,
    GIT_OID_MINPREFIXLEN,
    GIT_OID_RAWSZ,
    GIT_OID_HEXSZ,
)


cdef GitOid _empty_GitOid():
    cdef GitOid empty = GitOid.__new__(GitOid)
    empty._oid = <const_git_oid*>cython.address(empty._my_oid)
    return empty


cdef class GitOid:

    cdef const_git_oid *_oid

    cdef git_oid _my_oid

    cdef readonly int length

    cdef object _owner

    def __cinit__(GitOid self):
        self._oid = NULL
        self.length = GIT_OID_HEXSZ
        self._owner = None

    def __init__(GitOid self, hex=None, raw=None):
        if raw is not None and hex is not None:
            raise ValueError()
        elif raw is None and hex is None:
            raise ValueError()

        # FIXME: Check raw min length
        if hex is not None and len(hex) < GIT_OID_MINPREFIXLEN:
            raise ValueError(('OID is shorted than minimum length ({}): '
                              '{!r}').format(GIT_OID_MINPREFIXLEN, hex))
        elif hex is not None and len(hex) > GIT_OID_HEXSZ:
            raise ValueError('Length of hex OID is larger than {}: {!r}'.format(
                GIT_OID_RAWSZ, hex))
        elif raw is not None and len(raw) > GIT_OID_RAWSZ:
            raise ValueError('Length of raw OID is larger than {}: {!r}'.format(
                GIT_OID_RAWSZ, raw))
        elif raw is not None and not isinstance(raw, bytes):
            raise ValueError('Raw value should be {}, got {} instead'.format(
                bytes, type(raw)))

        cdef int error
        cdef size_t length
        cdef char *c_string

        self._oid = <const_git_oid*>cython.address(self._my_oid)
        if hex is not None:
            if isinstance(hex, unicode):
                hex = hex.encode('ascii')
            elif sys.version_info[0] > 2:
                raise TypeError('Expected {}, got {} instead'.format(
                    unicode, bytes))
            length = len(hex)
            c_string = hex
            error = git_oid_fromstrn(cython.address(self._my_oid),
                                     <const_char*>c_string, length)
            check_error(error)
            self.length = length
        elif raw is not None:
            c_string = raw
            git_oid_fromraw(cython.address(self._my_oid),
                            <const_uchar*>c_string)

    def _dealloc__(GitOid self):
        self._oid = NULL
        self._owner = None

    def __hash__(self):
        hash(self.raw)

    def __len__(self):
        return self.length

    def __richcmp__(GitOid self not None, other, int op):
        if isinstance(other, GitOid):
            other_hex = other.hex
        else:
            other_hex = other
        if op == 2: # ==
            return self.hex == other_hex
        elif op == 3: # !=
            return self.hex != other_hex
        elif op == 0: # <
            return self.hex < other_hex
        elif op == 1: # <= (not >)
            return not (self.hex > other_hex)
        elif op == 4: # >
            return self.hex > other_hex
        elif op == 5: # >= (not <)
            return not (self.hex < other_hex)

    cdef object format(GitOid self):
        assert_GitOid(self)
        cdef char *hex_str = <char*>stdlib.malloc(GIT_OID_HEXSZ)
        git_oid_fmt(hex_str, self._oid)
        try:
            py_hex_str = hex_str[:GIT_OID_HEXSZ]
        finally:
            stdlib.free(hex_str)
        return py_hex_str.decode('ascii')

    property hex:
        def __get__(GitOid self):
            assert_GitOid(self)
            return self.format()[:self.length]

    property raw:
        def __get__(GitOid self):
            assert_GitOid(self)
            cdef unsigned char *string = self._oid.id
            cdef bytes py_string = string[:GIT_OID_RAWSZ]
            return py_string

    def __repr__(GitOid self):
        return 'GitOid({!r})'.format(self.hex)


cdef GitOid make_oid(object owner, const_git_oid *oidp):
    if oidp is NULL:
        return None
    cdef GitOid oid = _empty_GitOid()
    oid._owner = owner
    oid._oid = oidp
    assert_GitOid(oid)
    return oid
