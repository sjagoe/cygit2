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

from _remote cimport (
    git_remote_create,
    git_remote_free,
    git_remote_get_refspec,
    git_remote_load,
    git_remote_name,
    git_remote_refspec_count,
    git_remote_rename,
    git_remote_save,
    git_remote_set_url,
    git_remote_url,
)

from _refspec cimport git_refspec_dst, git_refspec_src


cdef GitRemote _load_GitRemote(git_repository *repo, const char *name):
    cdef int error
    cdef git_remote *gitremote
    error = git_remote_load(cython.address(gitremote), repo, name)
    check_error(error)
    cdef GitRemote remote = GitRemote.__new__(GitRemote)
    remote._remote = gitremote
    return remote


cdef GitRemote _create_GitRemote(git_repository *repo, const char * name,
                                 const char *url):
    cdef int error
    cdef git_remote *gitremote
    error = git_remote_create(cython.address(gitremote), repo, name, url)
    check_error(error)
    cdef GitRemote remote = GitRemote.__new__(GitRemote)
    remote._remote = gitremote
    return remote


cdef class GitRemote:

    cdef git_remote *_remote

    def __cinit__(GitRemote self):
        self._remote = NULL

    def __dealloc__(GitRemote self):
        if self._remote is not NULL:
            git_remote_free(self._remote)

    def get_refspec(GitRemote self, number):
        assert_GitRemote(self)
        cdef const git_refspec *refspec
        cdef size_t c_number = number
        cdef GitRefspec gitrefspec = GitRefspec.__new__(GitRefspec)
        gitrefspec._owner = self
        gitrefspec._refspec = git_remote_get_refspec(self._remote, c_number)
        return gitrefspec

    def save(self):
        assert_GitRemote(self)
        cdef int error
        error = git_remote_save(self._remote)
        check_error(error)

    property name:
        def __get__(GitRemote self):
            assert_GitRemote(self)
            cdef const char *c_name = git_remote_name(self._remote)
            cdef bytes py_name = c_name
            return py_name.decode(DEFAULT_ENCODING)

        def __set__(GitRemote self, name):
            assert_GitRemote(self)
            cdef int error
            cdef bytes py_name
            cdef const char * c_name
            if isinstance(name, unicode):
                py_name = name.encode(DEFAULT_ENCODING)
            elif isinstance(name, bytes):
                py_name = name
            else:
                raise TypeError(
                    'Expected \'name\' to be {} or {}, got {}'.format(
                        unicode, bytes, type(name)))

            c_name = py_name
            error = git_remote_rename(self._remote, c_name, NULL, NULL)
            check_error(error)

    property refspec_count:
        def __get__(GitRemote self):
            assert_GitRemote(self)
            cdef size_t count = git_remote_refspec_count(self._remote)
            return count

    property url:
        def __get__(GitRemote self):
            assert_GitRemote(self)
            cdef const char *c_url = git_remote_url(self._remote)
            cdef bytes py_url = c_url
            return py_url.decode(DEFAULT_ENCODING)

        def __set__(GitRemote self, url):
            assert_GitRemote(self)
            cdef int error
            cdef bytes py_url
            cdef const char * c_url
            if isinstance(url, unicode):
                py_url = url.encode(DEFAULT_ENCODING)
            elif isinstance(url, bytes):
                py_url = url
            else:
                raise TypeError(
                    'Expected \'url\' to be {} or {}, got {}'.format(
                        unicode, bytes, type(url)))

            c_url = py_url
            error = git_remote_set_url(self._remote, c_url)
            check_error(error)
