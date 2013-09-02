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

from _clone cimport git_clone
from _commit cimport git_commit_lookup_prefix
from _object cimport git_object_lookup_prefix
from _revparse cimport git_revparse_single
from _strarray cimport git_strarray, git_strarray_free
from _tree cimport git_tree_lookup_prefix

from _blob cimport (
    git_blob_create_frombuffer,
    git_blob_create_fromdisk,
    git_blob_create_fromworkdir,
)

from _odb cimport (
    git_odb_hash,
    git_odb_hashfile,
)

from _refs cimport (
    git_reference_lookup,
    git_reference_list,
    git_reference_is_valid_name,
)

from _repository cimport (
    git_repository_config,
    git_repository_discover,
    git_repository_free,
    git_repository_head,
    git_repository_head_detached,
    git_repository_head_orphan,
    git_repository_init,
    git_repository_is_bare,
    git_repository_is_empty,
    git_repository_odb,
    git_repository_open,
    git_repository_path,
    git_repository_workdir,
)

from _types cimport (
    MAXPATHLEN,
    git_repository,
    git_tree,
    git_otype,
)


cdef _open_repository(git_repository **repo, path):
    cdef bytes bpath = _to_bytes(path)
    cdef int error
    error = git_repository_open(repo, bpath)
    check_error(error)


cdef class Repository:

    cdef git_repository *_repository

    def __cinit__(Repository self):
        self._repository = NULL

    def __init__(Repository self, path=None):
        if path is not None:
            _open_repository(cython.address(self._repository), path)
            assert_Repository(self)

    def __dealloc__(Repository self):
        if self._repository is not NULL:
            git_repository_free(self._repository)

    def close(Repository self):
        if self._repository is not NULL:
            git_repository_free(self._repository)
            self._repository = NULL

    cdef GitOdb odb(Repository self):
        cdef int error
        assert_Repository(self)
        cdef GitOdb odb = GitOdb()
        error = git_repository_odb(cython.address(odb._odb), self._repository)
        check_error(error)
        return odb

    @staticmethod
    def hash(data):
        cdef int error
        cdef GitOid oid = _empty_GitOid()
        cdef bytes py_data = _to_bytes(data)
        cdef size_t length = len(py_data)
        cdef const char *raw = py_data

        error = git_odb_hash(
            <git_oid*>oid._oid, raw, length, GIT_OBJ_BLOB)

        check_error(error)
        assert_GitOid(oid)

        return oid

    @staticmethod
    def hashfile(filepath):
        cdef int error
        cdef GitOid oid = _empty_GitOid()
        cdef bytes py_data = _to_bytes(filepath)
        cdef const char *path = py_data

        error = git_odb_hashfile(<git_oid*>oid._oid, path, GIT_OBJ_BLOB)

        check_error(error)
        assert_GitOid(oid)

        return oid

    ### Repository open and creation ###

    @classmethod
    def open(cls, path):
        repo = Repository()
        _open_repository(cython.address(repo._repository), path)
        return repo

    @classmethod
    def init(cls, path, bare=False):
        cdef bytes bpath = _to_bytes(path)
        cdef int error
        cdef Repository repo = Repository()
        error = git_repository_init(cython.address(repo._repository), bpath,
                                    bare)
        check_error(error)
        assert_Repository(repo)
        return repo

    @classmethod
    def clone(cls, url, path):
        cdef bytes burl = _to_bytes(url, u"ascii")
        cdef bytes bpath = _to_bytes(path)
        cdef int error
        cdef Repository repo = Repository()
        error = git_clone(cython.address(repo._repository), burl, bpath, NULL)
        check_error(error)
        assert_Repository(repo)
        return repo

    @classmethod
    def discover(cls, path, across_fs=False, ceiling_dirs=None):
        cdef int error
        cdef bytes out_path
        cdef char *c_ceiling_dirs = NULL
        cdef int c_across_fs = 0
        cdef bytes bpath = _to_bytes(path)
        cdef char *repo_path = <char*>stdlib.malloc(MAXPATHLEN)
        try:
            error = git_repository_discover(repo_path, MAXPATHLEN, bpath,
                                            c_across_fs, c_ceiling_dirs)
            check_error(error)
            out_path = repo_path
            return out_path.decode(DEFAULT_ENCODING)
        finally:
            stdlib.free(repo_path)

    ### Repository read protocol ###

    def lookup_reference(Repository self, name):
        assert_Repository(self)
        cdef bytes bname = _to_bytes(name)
        if git_reference_is_valid_name(bname) == 0:
            raise LibGit2ReferenceError('Invalid reference name {!r}'.format(
                name))
        cdef int error
        cdef Reference ref = Reference()
        error = git_reference_lookup(cython.address(ref._reference),
                                     self._repository, bname)
        try:
            check_error(error)
        except LibGit2ReferenceError:
            raise KeyError(name)
        return ref

    def lookup_commit(Repository self, GitOid oid):
        cdef int error
        assert_Repository(self)
        assert_GitOid(oid)
        cdef GitCommit commit = GitCommit(self)
        error = git_commit_lookup_prefix(
            <git_commit**>cython.address(commit._object),
            self._repository, oid._oid, oid.length)
        check_error(error)
        return commit

    def lookup_tree(Repository self, GitOid oid):
        cdef int error
        assert_Repository(self)
        assert_GitOid(oid)
        cdef GitTree tree = GitTree(self)
        error = git_tree_lookup_prefix(
            <git_tree**>cython.address(tree._object), self._repository, oid._oid,
            oid.length)
        check_error(error)
        return tree

    def listall_references(Repository self):
        cdef unsigned int index
        cdef int error
        cdef git_strarray arr
        cdef bytes py_bytes
        assert_Repository(self)
        error = git_reference_list(cython.address(arr), self._repository)
        check_error(error)
        try:
            items = []
            for index from 0 <= index < arr.count:
                py_bytes = arr.strings[index]
                items.append(py_bytes.decode(DEFAULT_ENCODING))
            return tuple(items)
        finally:
            git_strarray_free(cython.address(arr))

    cpdef lookup_object(Repository self, GitOid oid, EnumValue otype):
        cdef int error
        cdef git_object *_object

        assert_Repository(self)
        assert_GitOid(oid)
        error = git_object_lookup_prefix(
            cython.address(_object), self._repository, oid._oid,
            oid.length, <git_otype>otype.value)
        check_error(error)

        return _GitObject_from_git_object_pointer(self, _object)

    cpdef read(Repository self, GitOid oid):
        assert_GitOid(oid)
        cdef GitOdb odb = self.odb()
        return odb.read_prefix(oid)

    def status_ext(Repository self, include_untracked=True,
                   include_ignored=True, include_unmodified=False,
                   exclude_submodules=True, recurse_untracked_dirs=False,
                   list paths=None):
        cdef int error
        cdef git_status_options opts
        cdef git_strarray pathspec
        cdef bytes py_string
        assert_Repository(self)

        opts.version = GIT_STATUS_OPTIONS_VERSION
        opts.flags = 0
        opts.show = GIT_STATUS_SHOW_INDEX_AND_WORKDIR

        if include_untracked:
            opts.flags |= GIT_STATUS_OPT_INCLUDE_UNTRACKED
        if include_ignored:
            opts.flags |= GIT_STATUS_OPT_INCLUDE_IGNORED
        if include_unmodified:
            opts.flags |= GIT_STATUS_OPT_INCLUDE_UNMODIFIED
        if exclude_submodules:
            opts.flags |= GIT_STATUS_OPT_EXCLUDE_SUBMODULES
        if recurse_untracked_dirs:
            opts.flags |= GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS

        if paths is None:
            opts.flags |= GIT_STATUS_OPT_DISABLE_PATHSPEC_MATCH
            pathspec.strings = NULL
            pathspec.count = 0
        else:
            pathspec.strings = <char**>stdlib.malloc(sizeof(char*)*len(paths))
        try:
            if pathspec.strings is not NULL:
                for index, string in enumerate(paths):
                    py_string = _to_bytes(string)
                    pathspec.strings[index] = py_string
                pathspec.count = len(paths)

            opts.pathspec = pathspec

            result = {}
            error = git_status_foreach_ext(self._repository, cython.address(opts),
                                           _status_foreach_cb, <void*>result)
            check_error(error)
            return result
        finally:
            if pathspec.strings is not NULL:
                stdlib.free(pathspec.strings)

    def status(Repository self):
        cdef int error
        assert_Repository(self)
        result = {}
        error = git_status_foreach(self._repository, _status_foreach_cb,
                                   <void*>result)
        check_error(error)
        return result

    def revparse_single(Repository self, spec):
        cdef int error
        cdef bytes py_str = _to_bytes(spec)
        cdef git_object *_object

        error = git_revparse_single(cython.address(_object),
                                    self._repository, py_str)
        check_error(error)
        return _GitObject_from_git_object_pointer(self, _object)

    ### Repository write protocol ###

    def create_blob(Repository self, content):
        cdef int error
        cdef GitOid oid = _empty_GitOid()
        cdef bytes py_str = _to_bytes(content)
        cdef size_t length = len(py_str)
        cdef const_char *raw = py_str

        assert_Repository(self)

        error = git_blob_create_frombuffer(
            <git_oid*>oid._oid, self._repository, <const void*>raw, length)

        check_error(error)
        assert_GitOid(oid)

        return oid

    def create_blob_fromworkdir(Repository self, path):
        cdef int error
        cdef GitOid oid = _empty_GitOid()
        cdef bytes py_path = _to_bytes(path)
        cdef const_char *char_path = py_path

        assert_Repository(self)

        error = git_blob_create_fromworkdir(
            <git_oid*>oid._oid, self._repository, char_path)

        check_error(error)
        assert_GitOid(oid)

        return oid

    def create_blob_fromdisk(Repository self, path):
        cdef int error
        cdef GitOid oid = _empty_GitOid()
        cdef bytes py_path = _to_bytes(path)
        cdef const_char *char_path = py_path

        assert_Repository(self)

        error = git_blob_create_fromdisk(
            <git_oid*>oid._oid, self._repository, char_path)

        check_error(error)
        assert_GitOid(oid)

        return oid

    ### Special methods ###

    def __contains__(Repository self, GitOid oid):
        assert_Repository(self)
        try:
            obj = self.read(oid)
        except LibGit2Error:
            return False
        return obj is not None

    def __getitem__(Repository self, GitOid oid not None):
        assert_Repository(self)
        return self.lookup_object(oid, GitObjectType.ANY)

    def __iter__(Repository self):
        cdef int error
        cdef GitOdb odb = self.odb()
        return iter(odb.oids())

    ### Properties ###

    property is_bare:
        def __get__(Repository self):
            assert_Repository(self)
            return git_repository_is_bare(self._repository) != 0

    property is_empty:
        def __get__(Repository self):
            assert_Repository(self)
            return git_repository_is_empty(self._repository) != 0

    property head:
        def __get__(Repository self):
            cdef const_git_oid *oidp
            assert_Repository(self)
            cdef int error
            cdef git_reference *_reference
            cdef Reference reference
            error = git_repository_head(cython.address(_reference),
                                        self._repository)
            check_error(error)
            reference = Reference()
            reference._reference = _reference
            return reference

    property head_is_detached:
        def __get__(Repository self):
            assert_Repository(self)
            return git_repository_head_detached(self._repository) != 0

    property head_is_orphaned:
        def __get__(Repository self):
            assert_Repository(self)
            return git_repository_head_orphan(self._repository) != 0

    property config:
        def __get__(Repository self):
            cdef int error
            assert_Repository(self)
            cdef Config conf = Config()
            git_config_free(conf._config) # FIXME
            error = git_repository_config(cython.address(conf._config),
                                          self._repository)
            check_error(error)
            return conf

    property path:
        def __get__(Repository self):
            assert_Repository(self)
            cdef bytes py_string = git_repository_path(self._repository)
            return py_string.decode(DEFAULT_ENCODING)

    property workdir:
        def __get__(Repository self):
            assert_Repository(self)
            if self.is_bare:
                return None
            cdef bytes py_string = git_repository_workdir(self._repository)
            return py_string.decode(DEFAULT_ENCODING)
