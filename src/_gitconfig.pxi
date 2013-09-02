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

from _config cimport (
    git_config_new, git_config_free, git_config_open_ondisk,
    git_config_add_file_ondisk, const_git_config_entry, git_config_get_entry,
    git_config_get_int64, git_config_get_bool, git_config_get_string,
    git_config_get_multivar, git_config_set_string, git_config_set_bool,
    git_config_set_int64, git_config_set_multivar, git_config_delete_entry,
    git_config_foreach, git_config_find_global, git_config_find_system,
)


class GitItemNotFound(Exception): pass


cdef object _get_config_entry(git_config *config, name):
    cdef int error
    cdef int64_t c_int
    cdef int c_bool
    cdef char *c_string
    cdef bytes py_string
    cdef bytes bname = _to_bytes(name)

    error = git_config_get_int64(
        cython.address(c_int), config, bname)
    if error == GIT_OK:
        return c_int

    error = git_config_get_bool(
        cython.address(c_bool), config, bname)
    if error == GIT_OK:
        return bool(c_bool)

    error = git_config_get_string(
        <const_char**>cython.address(c_string), config, bname)
    if error == GIT_OK:
        py_string = c_string
        return py_string.decode(DEFAULT_ENCODING)

    if error == GIT_ENOTFOUND:
        raise GitItemNotFound()
    check_error(error)


cdef int _git_config_get_multivar_cb(const_git_config_entry *entry,
                                     void *payload):
    cdef list result = <object>payload
    if entry is NULL or entry.value is NULL:
        return GIT_ENOTFOUND
    value = <char*>entry.value
    result.append(value.decode(DEFAULT_ENCODING))
    return 0


cdef int _git_config_foreach_callback(const_git_config_entry *entry,
                                      void *c_payload):
    cdef bytes entry_name
    cdef bytes entry_value
    cdef object py_callback
    cdef object py_payload
    cdef tuple payload = <object>c_payload
    py_callback, py_payload = payload
    entry_name = entry.name
    # FIXME?
    entry_value = entry.value

    if py_payload is None:
        py_callback(entry_name.decode(DEFAULT_ENCODING), entry.value)
    else:
        py_callback(entry_name.decode(DEFAULT_ENCODING), entry.value, py_payload)
    return 0


def _Config_get_global_config():
    cdef int error
    cdef bytes py_path
    cdef char *path = <char*>stdlib.malloc(GIT_PATH_MAX+1)
    try:
        path[GIT_PATH_MAX] = '\0'
        error = git_config_find_global(path, GIT_PATH_MAX)
        if error == GIT_ENOTFOUND:
            return Config()
        check_error(error)
        py_path = path
        return Config(py_path)
    finally:
        stdlib.free(path)


def _Config_get_system_config():
    cdef int error
    cdef bytes py_path
    cdef char *path = <char*>stdlib.malloc(GIT_PATH_MAX)
    try:
        error = git_config_find_system(path, GIT_PATH_MAX)
        try:
            check_error(error)
        except LibGit2OSError as e:
            raise IOError(unicode(e))
        py_path = path
        return Config(py_path)
    finally:
        stdlib.free(path)


cdef class Config:

    cdef git_config *_config

    def __cinit__(Config self):
        self._config = NULL

    def __init__(Config self, filename=None):
        cdef int error
        cdef bytes c_filename
        if filename is not None:
            c_filename = _to_bytes(filename)
            error = git_config_open_ondisk(cython.address(self._config),
                                           c_filename)
        else:
            error = git_config_new(cython.address(self._config))
        check_error(error)

    def __dealloc__(Config self):
        if self._config is not NULL:
            git_config_free(self._config)

    get_global_config = staticmethod(_Config_get_global_config)

    get_system_config = staticmethod(_Config_get_system_config)

    def add_file(Config self, path, level=0, force=0):
        cdef int error
        cdef bytes c_path = _to_bytes(path)
        cdef unsigned int c_level = level
        cdef int c_force = force
        error = git_config_add_file_ondisk(self._config, c_path, c_level,
                                           c_force)
        check_error(error)

    def get_multivar(Config self, path, regexp=None):
        cdef int error
        cdef bytes py_regexp
        cdef const_char *c_regexp = NULL
        cdef bytes py_string = _to_bytes(path)
        cdef const_char *c_string = py_string
        if regexp is not None:
            py_regexp = _to_bytes(regexp)
            c_regexp = py_regexp
        result = []
        error = git_config_get_multivar(
            self._config, c_string, c_regexp,
            _git_config_get_multivar_cb, <void*>result)

        if error == GIT_ENOTFOUND and len(result) > 0:
            return result

        check_error(error)

        return result

    def set_multivar(Config self, name, regexp, value):
        cdef int error
        cdef bytes py_name = _to_bytes(name)
        cdef const_char *c_name = py_name
        cdef bytes py_regexp = _to_bytes(regexp)
        cdef const_char *c_regexp = py_regexp
        cdef bytes py_value = _to_bytes(value)
        cdef const_char *c_value = py_value

        error = git_config_set_multivar(self._config, c_name, c_regexp, c_value)
        check_error(error)

    def foreach(Config self, object callback, object py_payload=None):
        cdef int error
        cdef tuple payload = (callback, py_payload)
        error = git_config_foreach(
            self._config, _git_config_foreach_callback, <void*>payload)
        check_error(error)

    cdef get_entry(Config self, name):
        cdef bytes bname = _to_bytes(name)
        cdef int error
        cdef const_git_config_entry *entry
        error = git_config_get_entry(
            cython.address(entry), self._config, bname)
        check_error(error)
        value = <char*>entry.value
        level = entry.level
        return level, value.decode(DEFAULT_ENCODING)

    cdef get_value(Config self, name):
        try:
            return _get_config_entry(self._config, name)
        except GitItemNotFound:
            raise KeyError(name)
        except LibGit2Error as e:
            raise ValueError(e.args[0].decode(DEFAULT_ENCODING))

    cdef set_value(Config self, name, value):
        cdef int error
        cdef int64_t c_int
        cdef int c_bool
        cdef char *c_string
        cdef bytes py_string
        cdef bytes bname = _to_bytes(name)
        cdef git_config *config = self._config

        if isinstance(value, bool):
            c_bool = value
            error = git_config_set_bool(config, bname, c_bool)
            check_error(error)

        elif isinstance(value, int):
            c_int = value
            error = git_config_set_int64(config, bname, c_int)
            check_error(error)

        elif isinstance(value, unicode) or isinstance(value, bytes):
            if isinstance(value, unicode):
                py_string = value.encode(DEFAULT_ENCODING)
            else:
                py_string = value
            c_string = py_string

            error = git_config_set_string(config, bname, c_string)
            check_error(error)

        else:
            raise ValueError('Unhandled type for value {!r}'.format(value))

    cdef delete_entry(Config self, name):
        cdef int error
        cdef bytes bname = _to_bytes(name)
        cdef git_config *config = self._config
        error = git_config_delete_entry(config, bname)
        check_error(error)

    cdef _check_name(Config self, name):
        if not isinstance(name, (bytes, str, unicode)):
            raise TypeError(type(name))

    def __setitem__(Config self, name, value):
        self._check_name(name)
        self.set_value(name, value)

    def __getitem__(Config self, name):
        self._check_name(name)
        return self.get_value(name)

    def __delitem__(Config self, name):
        self._check_name(name)
        self.delete_entry(name)

    def __contains__(Config self, name):
        self._check_name(name)
        try:
            self.get_entry(name)
        except LibGit2ConfigError:
            return False
        return True
