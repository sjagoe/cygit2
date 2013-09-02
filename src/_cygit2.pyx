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

from _status cimport \
    git_status_t, \
    git_status_foreach, git_status_foreach_ext, \
    git_status_options, \
    \
    GIT_STATUS_CURRENT, \
    GIT_STATUS_INDEX_NEW, \
    GIT_STATUS_INDEX_MODIFIED, \
    GIT_STATUS_INDEX_DELETED, \
    GIT_STATUS_INDEX_RENAMED, \
    GIT_STATUS_INDEX_TYPECHANGE, \
    GIT_STATUS_WT_NEW, \
    GIT_STATUS_WT_MODIFIED, \
    GIT_STATUS_WT_DELETED, \
    GIT_STATUS_WT_TYPECHANGE, \
    GIT_STATUS_IGNORED, \
    \
    GIT_STATUS_OPT_INCLUDE_UNTRACKED, \
    GIT_STATUS_OPT_INCLUDE_IGNORED, \
    GIT_STATUS_OPT_INCLUDE_UNMODIFIED, \
    GIT_STATUS_OPT_EXCLUDE_SUBMODULES, \
    GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS, \
    GIT_STATUS_OPT_DISABLE_PATHSPEC_MATCH, \
    GIT_STATUS_SHOW_INDEX_AND_WORKDIR, \
    GIT_STATUS_OPTIONS_VERSION

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


cdef ComposableEnumValue _GitStatus_from_uint(unsigned int flags):
    if flags == GitStatus.CURRENT.value:
        return GitStatus.CURRENT
    value = None
    for item in (GitStatus.INDEX_NEW,
                 GitStatus.INDEX_MODIFIED,
                 GitStatus.INDEX_DELETED,
                 GitStatus.INDEX_RENAMED,
                 GitStatus.INDEX_TYPECHANGE,
                 GitStatus.WT_NEW,
                 GitStatus.WT_MODIFIED,
                 GitStatus.WT_DELETED,
                 GitStatus.WT_TYPECHANGE,
                 GitStatus.IGNORED):
        if value is None and (flags & item.value) == item.value:
            value = item
        elif (flags & item.value) == item.value:
            value |= item
    if item is None:
        # FIXME
        return GitStatus.CURRENT
    return value


cdef class GitStatus:

    CURRENT          = ComposableEnumValue('GitStatus.CURRENT',
                                           GIT_STATUS_CURRENT)
    INDEX_NEW        = ComposableEnumValue('GitStatus.INDEX_NEW',
                                           GIT_STATUS_INDEX_NEW)
    INDEX_MODIFIED   = ComposableEnumValue('GitStatus.INDEX_MODIFIED',
                                           GIT_STATUS_INDEX_MODIFIED)
    INDEX_DELETED    = ComposableEnumValue('GitStatus.INDEX_DELETED',
                                           GIT_STATUS_INDEX_DELETED)
    INDEX_RENAMED    = ComposableEnumValue('GitStatus.INDEX_RENAMED',
                                           GIT_STATUS_INDEX_RENAMED)
    INDEX_TYPECHANGE = ComposableEnumValue('GitStatus.INDEX_TYPECHANGE',
                                           GIT_STATUS_INDEX_TYPECHANGE)
    WT_NEW           = ComposableEnumValue('GitStatus.WT_NEW',
                                           GIT_STATUS_WT_NEW)
    WT_MODIFIED      = ComposableEnumValue('GitStatus.WT_MODIFIED',
                                           GIT_STATUS_WT_MODIFIED)
    WT_DELETED       = ComposableEnumValue('GitStatus.WT_DELETED',
                                           GIT_STATUS_WT_DELETED)
    WT_TYPECHANGE    = ComposableEnumValue('GitStatus.WT_TYPECHANGE',
                                           GIT_STATUS_WT_TYPECHANGE)
    IGNORED          = ComposableEnumValue('GitStatus.IGNORED',
                                           GIT_STATUS_IGNORED)

    cdef ComposableEnumValue _flags

    @classmethod
    def _from_uint(cls, unsigned int flags):
        return _GitStatus_from_uint(flags)

    cpdef unsigned int _to_uint(GitStatus self):
        return self._flags.value

    def __init__(GitStatus self, ComposableEnumValue flags):
        self._flags = flags

    def __repr__(GitStatus self):
        return 'GitStatus({!r})'.format(self._flags)

    def __richcmp__(GitStatus self, GitStatus other not None, int op):
        if op == 2: # ==
            return self._flags == other._flags
        elif op == 3: # !=
            return self._flags != other._flags
        elif op == 0: # <
            return self._flags < other._flags
        elif op == 1: # <=
            return self._flags <= other._flags
        elif op == 4: # >
            return self._flags > other._flags
        elif op == 5: # >=
            return self._flags >= other._flags

    property current:
        def __get__(GitStatus self):
            return self._flags == self.CURRENT

    property index_new:
        def __get__(GitStatus self):
            return (self._flags & self.INDEX_NEW) == self.INDEX_NEW

    property index_modified:
        def __get__(GitStatus self):
            return (self._flags & self.INDEX_MODIFIED) == \
                self.INDEX_MODIFIED

    property index_deleted:
        def __get__(GitStatus self):
            return (self._flags & self.INDEX_DELETED) == \
                self.INDEX_DELETED

    property index_renamed:
        def __get__(GitStatus self):
            return (self._flags & self.INDEX_RENAMED) == \
                self.INDEX_RENAMED

    property index_typechange:
        def __get__(GitStatus self):
            return (self._flags & self.INDEX_TYPECHANGE) == \
                self.INDEX_TYPECHANGE

    property wt_new:
        def __get__(GitStatus self):
            return (self._flags & self.WT_NEW) == self.WT_NEW

    property wt_modified:
        def __get__(GitStatus self):
            return (self._flags & self.WT_MODIFIED) == \
                self.WT_MODIFIED

    property wt_deleted:
        def __get__(GitStatus self):
            return (self._flags & self.WT_DELETED) == \
                self.WT_DELETED

    property wt_typechange:
        def __get__(GitStatus self):
            return (self._flags & self.WT_TYPECHANGE) == \
                self.WT_TYPECHANGE

    property ignored:
        def __get__(GitStatus self):
            return (self._flags & self.IGNORED) == self.IGNORED


cdef int _status_foreach_cb(const_char *path,
                            unsigned int flags, void *payload):
    result = <object>payload
    cdef bytes py_path = <char*>path
    result[py_path.decode(DEFAULT_ENCODING)] = GitStatus(_GitStatus_from_uint(flags))
    return GIT_OK
