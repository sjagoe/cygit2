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
from _types cimport git_refspec, git_remote, git_repository

from _refspec cimport git_refspec_dst, git_refspec_src


cdef class GitRefspec:

    cdef const git_refspec * _refspec

    # Keep a reference to the cygit2 object that owns the refspec object
    cdef object _owner

    def __cinit__(self):
        self._refspec = NULL
        self._owner = None

    def __dealloc__(self):
        self._owner = None
        self._refspec = NULL

    property source:
        def __get__(self):
            cdef const char *c_source
            cdef bytes source
            c_source = git_refspec_src(self._refspec)
            source = c_source
            return source.decode(DEFAULT_ENCODING)

    property dest:
        def __get__(self):
            cdef const char *c_dest
            cdef bytes dest
            c_dest = git_refspec_dst(self._refspec)
            dest = c_dest
            return dest.decode(DEFAULT_ENCODING)
