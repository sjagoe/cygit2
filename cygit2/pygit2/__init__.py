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

from cygit2._cygit2 import (
    Config,
    GitCommit as Commit,
    GitObjectType,
    GitOid as Oid,
    GitReferenceType,
    GitSignature as Signature,
)
from cygit2._cygit2 import LibGit2Error

from .blob import Blob
from .repository import (
    Repository,
    discover_repository,
    hash,
    hashfile,
    init_repository,
)

GIT_DIFF_INCLUDE_UNMODIFIED = None
GIT_REF_OID = GitReferenceType.OID
GIT_REF_SYMBOLIC = GitReferenceType.SYMBOLIC
GIT_OBJ_ANY = GitObjectType.ANY
GIT_OBJ_BLOB = GitObjectType.BLOB
GIT_OBJ_COMMIT = GitObjectType.COMMIT
GIT_SORT_TIME = None
GIT_SORT_REVERSE = None

GIT_STATUS_CURRENT = 0
GIT_STATUS_INDEX_DELETED = 0
GIT_STATUS_INDEX_MODIFIED = 0
GIT_STATUS_INDEX_NEW = 0
GIT_STATUS_WT_DELETED = 0
GIT_STATUS_WT_MODIFIED = 0
GIT_STATUS_WT_NEW = 0


GitError = LibGit2Error
