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
import logging

from cygit2._cygit2 import (
    GitOid,
    Repository as BaseRepository,
)
from cygit2._cygit2 import (
    LibGit2Error,
    LibGit2OSError,
)

from .object import Object


logger = logging.getLogger(__name__)


def init_repository(path, bare=False):
    return Repository.init(path, bare=bare)


def discover_repository(path, across_fs=False, ceiling_dirs=None):
    return Repository.discover(path, across_fs=across_fs,
                               ceiling_dirs=ceiling_dirs)


def hash(data):
    return BaseRepository.hash(data)


def hashfile(filepath):
    return BaseRepository.hashfile(filepath)


class Repository(BaseRepository):

    def __getitem__(self, oid):
        if not isinstance(oid, GitOid):
            oid = GitOid(hex=oid)
        try:
            core = super(Repository, self).__getitem__(oid)
            return Object.convert(core)
        except LibGit2Error:
            raise KeyError(oid)

    def __contains__(self, oid):
        if not isinstance(oid, GitOid):
            oid = GitOid(hex=oid)
        try:
            return super(Repository, self).__contains__(oid)
        except KeyError:
            return False

    def read(self, oid):
        if not isinstance(oid, GitOid):
            oid = GitOid(hex=oid)
        try:
            return super(Repository, self).read(oid)
        except LibGit2Error:
            raise KeyError(oid)

    def create_blob_fromworkdir(self, path):
        try:
            return super(Repository, self).create_blob_fromworkdir(path)
        except LibGit2OSError:
            raise KeyError(path)
