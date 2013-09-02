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
import sys

from libc cimport stdlib
from libc.stdint cimport int64_t

import cython

from libc.string cimport const_char, const_uchar

from _types cimport \
    const_git_signature, \
    git_blob, \
    git_commit, \
    git_config, \
    git_object, \
    git_time_t, \
    git_reference, \
    git_reflog, \
    const_git_reflog_entry, \
    git_ref_t, \
    git_tree_entry, \
    const_git_tree_entry, \
    git_off_t, \
    \
    GIT_PATH_MAX, \
    MAXPATHLEN

include "_encoding.pxi"
include "_error.pxi"
include "_enum.pxi"
include "_cygit2_types.pxi"
include "_gitoid.pxi"
include "_gitodb.pxi"
include "_gitsignature.pxi"
include "_gitobject.pxi"
include "_gitcommit.pxi"
include "_gitblob.pxi"
include "_gittree.pxi"
include "_gitconfig.pxi"
include "_gitreference.pxi"
include "_gitrepository.pxi"
include "_gitstatus.pxi"
