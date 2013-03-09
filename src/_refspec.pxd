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

    char *git_refspec_src(git_refspec *refspec)

    char *git_refspec_dst(git_refspec *refspec)

    int git_refspec_force(git_refspec *refspec)

    int git_refspec_src_matches(git_refspec *refspec, char *refname)

    int git_refspec_dst_matches(git_refspec *refspec, char *refname)

    int git_refspec_transform(char *out, size_t outlen, git_refspec *spec, char *name)

    int git_refspec_rtransform(char *out, size_t outlen, git_refspec *spec, char *name)
