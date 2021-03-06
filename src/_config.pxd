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

# This code was automatically generated by CWrap version 0.0.0

from libc.stdint cimport int32_t, int64_t

from _types cimport \
    git_config


cdef extern from "git2.h":

    cdef enum:
        GIT_CONFIG_LEVEL_SYSTEM
        GIT_CONFIG_LEVEL_XDG
        GIT_CONFIG_LEVEL_GLOBAL
        GIT_CONFIG_LEVEL_LOCAL
        GIT_CONFIG_HIGHEST_LEVEL

    cdef struct git_config_entry:
        char *name
        char *value
        unsigned int level

    ctypedef git_config_entry const_git_config_entry "const git_config_entry"

    ctypedef int (*git_config_foreach_cb)(git_config_entry *, void *)

    cdef struct git_config_backend:
        unsigned int version
        git_config *cfg
        int (*open)(git_config_backend *, unsigned int)
        int (*get)(git_config_backend *, char *, git_config_entry **)
        int (*get_multivar)(git_config_backend *, char *, char *, git_config_foreach_cb, void *)
        int (*set)(git_config_backend *, char *, char *)
        int (*set_multivar)(git_config_backend *, char *, char *, char *)
        int (*del_)(git_config_backend *, char *)
        int (*foreach)(git_config_backend *, char *, git_config_foreach_cb, void *)
        int (*refresh)(git_config_backend *)
        void (*free)(git_config_backend *)

    cdef enum git_cvar_t:
        GIT_CVAR_FALSE
        GIT_CVAR_TRUE
        GIT_CVAR_INT32
        GIT_CVAR_STRING

    cdef struct git_cvar_map:
        git_cvar_t cvar_type
        char *str_match
        int map_value

    int git_config_find_global(char *out, size_t length)

    int git_config_find_xdg(char *out, size_t length)

    int git_config_find_system(char *out, size_t length)

    int git_config_open_default(git_config **out)

    int git_config_new(git_config **out)

    int git_config_add_backend(git_config *cfg, git_config_backend *file, unsigned int level, int force)

    int git_config_add_file_ondisk(git_config *cfg, char *path, unsigned int level, int force)

    int git_config_open_ondisk(git_config **out, char *path)

    int git_config_open_level(git_config **out, git_config *parent, unsigned int level)

    int git_config_refresh(git_config *cfg)

    void git_config_free(git_config *cfg)

    int git_config_get_entry(git_config_entry **out, git_config *cfg, char *name)

    int git_config_get_int32(int32_t *out, git_config *cfg, char *name)

    int git_config_get_int64(int64_t *out, git_config *cfg, char *name)

    int git_config_get_bool(int *out, git_config *cfg, char *name)

    int git_config_get_string(char **out, git_config *cfg, char *name)

    int git_config_get_multivar(git_config *cfg, char *name, char *regexp, git_config_foreach_cb callback, void *payload)

    int git_config_set_int32(git_config *cfg, char *name, int32_t value)

    int git_config_set_int64(git_config *cfg, char *name, int64_t value)

    int git_config_set_bool(git_config *cfg, char *name, int value)

    int git_config_set_string(git_config *cfg, char *name, char *value)

    int git_config_set_multivar(git_config *cfg, char *name, char *regexp, char *value)

    int git_config_delete_entry(git_config *cfg, char *name)

    int git_config_foreach(git_config *cfg, git_config_foreach_cb callback, void *payload)

    int git_config_foreach_match(git_config *cfg, char *regexp, git_config_foreach_cb callback, void *payload)

    int git_config_get_mapped(int *out, git_config *cfg, char *name, git_cvar_map *maps, size_t map_n)

    int git_config_lookup_map_value(int *out, git_cvar_map *maps, size_t map_n, char *value)

    int git_config_parse_bool(int *out, char *value)

    int git_config_parse_int32(int32_t *out, char *value)

    int git_config_parse_int64(int64_t *out, char *value)
