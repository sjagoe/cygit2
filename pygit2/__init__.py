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

from cygit2._cygit2 import GitOid, Repository as BaseRepository, \
    GitSignature as Signature, Config, GitReferenceType
from cygit2._cygit2 import LibGit2Error

GIT_OBJ_COMMIT = None
GIT_DIFF_INCLUDE_UNMODIFIED = None
GitError = None
GIT_REF_OID = GitReferenceType.OID
GIT_REF_SYMBOLIC = GitReferenceType.SYMBOLIC
GIT_OBJ_ANY = None
GIT_OBJ_BLOB = None
GIT_OBJ_COMMIT = None
init_repository = None
discover_repository = None
Commit = None
hashfile = None
GIT_SORT_TIME = None
GIT_SORT_REVERSE = None

GIT_STATUS_CURRENT = 0
GIT_STATUS_INDEX_DELETED = 0
GIT_STATUS_INDEX_MODIFIED = 0
GIT_STATUS_INDEX_NEW = 0
GIT_STATUS_WT_DELETED = 0
GIT_STATUS_WT_MODIFIED = 0
GIT_STATUS_WT_NEW = 0


def init_repository(path, bare=False):
    return Repository.init(path, bare=bare)


class Repository(BaseRepository):

    def __getitem__(self, oid_hex):
        if isinstance(oid_hex, GitOid):
            oid = oid_hex
        else:
            oid = GitOid(oid_hex)
        try:
            return super(Repository, self).__getitem__(oid)
        except LibGit2Error:
            raise KeyError(oid_hex)

    def __contains__(self, oid_hex):
        if isinstance(oid_hex, GitOid):
            oid = oid_hex
        else:
            oid = GitOid(oid_hex)
        try:
            return super(Repository, self).__contains__(oid)
        except LibGit2Error:
            raise KeyError(oid_hex)

    def read(self, oid_hex):
        if isinstance(oid_hex, GitOid):
            oid = oid_hex
        else:
            oid = GitOid(oid_hex)
        try:
            return super(Repository, self).read(oid)
        except LibGit2Error:
            raise KeyError(oid_hex)
