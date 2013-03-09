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

cdef extern from "git2.h":

    cdef struct git_oid:
        unsigned char id[20]

    ctypedef git_oid git_oid

    ctypedef git_oid const_git_oid "const git_oid"

    int git_oid_fromstr(git_oid *out, char *str)

    int git_oid_fromstrn(git_oid *out, char *str, size_t length)

    void git_oid_fromraw(git_oid *out, unsigned char *raw)

    void git_oid_fmt(char *out, git_oid *id)

    void git_oid_pathfmt(char *out, git_oid *id)

    char *git_oid_allocfmt(git_oid *id)

    char *git_oid_tostr(char *out, size_t n, git_oid *id)

    void git_oid_cpy(git_oid *out, git_oid *src)

    int git_oid_cmp(git_oid *a, git_oid *b)

    int git_oid_equal(git_oid *a, git_oid *b)

    int git_oid_ncmp(git_oid *a, git_oid *b, size_t len)

    int git_oid_streq(git_oid *id, char *str)

    int git_oid_iszero(git_oid *id)

    ctypedef git_oid_shorten git_oid_shorten

    cdef struct git_oid_shorten:
        pass

    git_oid_shorten *git_oid_shorten_new(size_t min_length)

    int git_oid_shorten_add(git_oid_shorten *os, char *text_id)

    void git_oid_shorten_free(git_oid_shorten *os)
