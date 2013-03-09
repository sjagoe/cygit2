# -*- coding: utf-8 -*-
#
# Copyright 2013 The cygit2 contributors
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

# FIXME: I am not sure about default filesystem encoding ...

cdef extern from "Python.h":
    cdef char *Py_FileSystemDefaultEncoding
    cdef char *PyUnicode_GetDefaultEncoding()


cdef bytes _encoding
cdef unicode DEFAULT_ENCODING


if Py_FileSystemDefaultEncoding is not NULL:
    _encoding = Py_FileSystemDefaultEncoding
    DEFAULT_ENCODING = _encoding.decode('ascii')
else:
    _encoding = PyUnicode_GetDefaultEncoding()
    DEFAULT_ENCODING = _encoding.decode('ascii')


# FIXME: Signature
cdef bytes _to_bytes(object string, unicode encoding=None):
    if encoding is None:
        encoding = DEFAULT_ENCODING
    if isinstance(string, bytes):
        return string
    else:
        return string.encode(encoding)
