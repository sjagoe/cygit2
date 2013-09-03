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

from _types cimport git_remote, git_repository

from _remote cimport (
    git_remote_free,
    git_remote_load,
    git_remote_name,
    git_remote_url,
)


cdef GitRemote _create_GitRemote(git_repository *repo, const char *name):
    cdef int error
    cdef GitRemote remote = GitRemote()
    cdef git_remote *gitremote
    error = git_remote_load(cython.address(gitremote), repo, name)
    check_error(error)
    remote._remote = gitremote
    return remote


cdef class GitRemote:

    cdef git_remote *_remote

    def __cinit__(GitRemote self):
        self._remote = NULL

    def __dealloc__(GitRemote self):
        if self._remote is not NULL:
            git_remote_free(self._remote)

    property name:
        def __get__(GitRemote self):
            assert_GitRemote(self)
            cdef const char *c_name = git_remote_name(self._remote)
            cdef bytes py_name = c_name
            return py_name.decode(DEFAULT_ENCODING)

    property url:
        def __get__(GitRemote self):
            assert_GitRemote(self)
            cdef const char *c_url = git_remote_url(self._remote)
            cdef bytes py_url = c_url
            return py_url.decode(DEFAULT_ENCODING)
