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

    int git_branch_create(git_reference **out, git_repository *repo, char *branch_name, git_commit *target, int force)

    int git_branch_delete(git_reference *branch)

    ctypedef int (*git_branch_foreach_cb)(char *, git_branch_t, void *)

    int git_branch_foreach(git_repository *repo, unsigned int list_flags, git_branch_foreach_cb branch_cb, void *payload)

    int git_branch_move(git_reference **out, git_reference *branch, char *new_branch_name, int force)

    int git_branch_lookup(git_reference **out, git_repository *repo, char *branch_name, git_branch_t branch_type)

    int git_branch_name(char **out, git_reference *ref)

    int git_branch_tracking(git_reference **out, git_reference *branch)

    int git_branch_tracking_name(char *tracking_branch_name_out, size_t buffer_size, git_repository *repo, char *canonical_branch_name)

    int git_branch_is_head(git_reference *branch)

    int git_branch_remote_name(char *remote_name_out, size_t buffer_size, git_repository *repo, char *canonical_branch_name)
