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

from libc cimport stdlib

import cython

from libc.string cimport const_char

from _types cimport \
    const_git_signature, \
    git_commit, \
    git_config, \
    git_object, \
    git_odb, \
    git_repository, \
    git_time_t, \
    git_reference, \
    git_reflog, \
    const_git_reflog_entry, \
    git_tree, \
    git_otype, \
    \
    GIT_OBJ_ANY, \
    GIT_OBJ_BAD, \
    GIT_OBJ__EXT1, \
    GIT_OBJ_COMMIT, \
    GIT_OBJ_TREE, \
    GIT_OBJ_BLOB, \
    GIT_OBJ_TAG, \
    GIT_OBJ__EXT2, \
    GIT_OBJ_OFS_DELTA, \
    GIT_OBJ_REF_DELTA, \
    GIT_REF_LISTALL

from _strarray cimport git_strarray, git_strarray_free

from _repository cimport \
    git_repository_odb, git_repository_open, git_repository_path, \
    git_repository_init, git_repository_free, git_repository_config

from _odb cimport \
    git_odb_read_prefix, git_odb_free, \
    git_odb_object, git_odb_object_free, git_odb_object_id, \
    git_odb_object_data, git_odb_object_size, git_odb_object_type

from _commit cimport \
    git_commit_free, git_commit_lookup_prefix, git_commit_id, \
    git_commit_message_encoding, git_commit_message, git_commit_time, \
    git_commit_time_offset, git_commit_committer, git_commit_author, \
    git_commit_tree, git_commit_tree_id, git_commit_parentcount, \
    git_commit_parent, git_commit_parent_id, git_commit_nth_gen_ancestor

from _signature cimport \
    git_signature_free

from _config cimport \
    git_config_free, \
    const_git_config_entry, git_config_get_entry

from _oid cimport \
    git_oid, const_git_oid, git_oid_fmt, git_oid_fromstrn

from _refs cimport \
    git_reference_free, git_reference_lookup, \
    git_reference_name, git_reference_target, git_reference_cmp, \
    git_reference_has_log, git_reference_list, git_reference_is_valid_name, \
    git_reference_is_branch, git_reference_is_remote

from _reflog cimport \
    git_reflog_free, git_reflog_read, git_reflog_entrycount, \
    git_reflog_entry_byindex, git_reflog_entry_id_new, \
    git_reflog_entry_id_old, git_reflog_entry_message

from _tree cimport \
    git_tree_free, git_tree_lookup_prefix, git_tree_id

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
    GIT_STATUS_SHOW_INDEX_THEN_WORKDIR, \
    GIT_STATUS_OPTIONS_VERSION

from _clone cimport git_clone

from _object cimport \
    git_object_lookup_prefix, \
    git_object_free, \
    git_object_type


include "_encoding.pxi"
include "_error.pxi"
include "_enum.pxi"


@cython.internal
cdef class _GitObjectType:

    cdef readonly EnumValue ANY
    cdef readonly EnumValue BAD
    cdef readonly EnumValue _EXT1
    cdef readonly EnumValue COMMIT
    cdef readonly EnumValue TREE
    cdef readonly EnumValue BLOB
    cdef readonly EnumValue TAG
    cdef readonly EnumValue _EXT2
    cdef readonly EnumValue OFS_DELTA
    cdef readonly EnumValue REF_DELTA

    def __init__(_GitObjectType self):
        self.ANY       = EnumValue('GitObjectType.ANY', GIT_OBJ_ANY)
        self.BAD       = EnumValue('GitObjectType.BAD', GIT_OBJ_BAD)
        self._EXT1     = EnumValue('GitObjectType._EXT1', GIT_OBJ__EXT1)
        self.COMMIT    = EnumValue('GitObjectType.COMMIT', GIT_OBJ_COMMIT)
        self.TREE      = EnumValue('GitObjectType.TREE', GIT_OBJ_TREE)
        self.BLOB      = EnumValue('GitObjectType.BLOB', GIT_OBJ_BLOB)
        self.TAG       = EnumValue('GitObjectType.TAG', GIT_OBJ_TAG)
        self._EXT2     = EnumValue('GitObjectType._EXT2', GIT_OBJ__EXT2)
        self.OFS_DELTA = EnumValue('GitObjectType.OFS_DELTA', GIT_OBJ_OFS_DELTA)
        self.REF_DELTA = EnumValue('GitObjectType.REF_DELTA', GIT_OBJ_REF_DELTA)

    cdef EnumValue _from_uint(_GitObjectType self, unsigned int type):
        for item in (self.ANY,
                     self.BAD,
                     self._EXT1,
                     self.COMMIT,
                     self.TREE,
                     self.BLOB,
                     self.TAG,
                     self._EXT2,
                     self.OFS_DELTA,
                     self.REF_DELTA):
            if type == item.value:
                return item


GitObjectType = _GitObjectType()


cdef class GitOdbObject:

    cdef git_odb_object *_object

    def __cinit__(GitOdbObject self):
        self._object = NULL

    def __dealloc__(GitOdbObject self):
        if self._object is not NULL:
            git_odb_object_free(self._object)

    property oid:
        def __get__(GitOdbObject self):
            cdef const_git_oid *oidp
            oidp = git_odb_object_id(self._object)
            return make_oid(self, oidp)

    property data:
        def __get__(GitOdbObject self):
            cdef const_char *string = <const_char*>git_odb_object_data(self._object)
            cdef bytes data = <char*>string
            return data

    property size:
        def __get__(GitOdbObject self):
            cdef size_t size = git_odb_object_size(self._object)
            return size

    property type:
        def __get__(GitOdbObject self):
            cdef _GitObjectType ObjType = GitObjectType
            cdef unsigned int utype = git_odb_object_type(self._object)
            return ObjType._from_uint(utype)

    def __repr__(GitOdbObject self):
        return '<GitOdbObject type={!r} size={!r}>'.format(self.type, self.size)


@cython.internal
cdef class GitOdb:

    cdef git_odb *_odb

    def __cinit__(GitOdb self):
        self._odb = NULL

    def __dealloc__(GitOdb self):
        if self._odb is not NULL:
            git_odb_free(self._odb)

    cdef GitOdbObject read_prefix(GitOdb self, GitOid oid):
        cdef int error
        cdef GitOdbObject obj = GitOdbObject()
        error = git_odb_read_prefix(cython.address(obj._object), self._odb,
                                    oid._oid, oid.length)
        check_error(error)
        return obj


cdef class GitSignature:

    cdef const_git_signature *_signature

    cdef object _owner

    def __cinit__(GitSignature self):
        self._signature = NULL

    def __init__(GitSignature self, object owner):
        self._owner = owner

    property name:
        def __get__(GitSignature self):
            cdef bytes py_string = self._signature.name
            return py_string.decode(DEFAULT_ENCODING)

    property email:
        def __get__(GitSignature self):
            cdef bytes py_string = self._signature.email
            return py_string.decode(DEFAULT_ENCODING)


cdef class GitCommit:

    cdef git_commit *_commit

    def __cinit__(GitCommit self):
        self._commit = NULL

    def __dealloc__(GitCommit self):
        if self._commit is not NULL:
            git_commit_free(self._commit)

    cdef object _get_message(GitCommit self):
        cdef bytes py_string
        cdef const_char *message = git_commit_message(self._commit)
        if message is NULL:
            return None
        py_string = <char*>message
        return py_string

    def ancestor(GitCommit self, unsigned int generation):
        cdef int error
        cdef GitCommit parent = GitCommit()
        error = git_commit_nth_gen_ancestor(cython.address(parent._commit),
                                            self._commit, generation)
        check_error(error)
        return parent

    def __richcmp__(GitCommit self, GitCommit other not None, int op):
        if op == 2: # ==
            return self.oid == other.oid
        elif op == 3: # !=
            return self.oid != other.oid
        elif op == 0: # <
            return self.oid < other.oid
        elif op == 1: # <= (not >)
            return not (self.oid > other.oid)
        elif op == 4: # >
            return self.oid > other.oid
        elif op == 5: # >= (not <)
            return not (self.oid < other.oid)

    property oid:
        def __get__(GitCommit self):
            cdef const_git_oid *oidp
            oidp = git_commit_id(self._commit)
            return make_oid(self, oidp)

    property message_encoding:
        def __get__(GitCommit self):
            cdef bytes py_string
            cdef const_char *encoding = git_commit_message_encoding(self._commit)
            if encoding is NULL:
                return None
            py_string = <char*>encoding
            return py_string.decode('ascii') # Will it always be ascii?

    property message:
        def __get__(GitCommit self):
            message = self._get_message()
            if message is None:
                return None
            encoding = self.encoding
            if encoding is None:
                encoding = DEFAULT_ENCODING
            return message.decode(encoding)

    property _message:
        def __get__(GitCommit self):
            return self._get_message()

    # FIXME: Convert time and time_offset into datetime
    property time:
        def __get__(GitCommit self):
            cdef git_time_t time = git_commit_time(self._commit)
            cdef object py_time = time
            return py_time

    property time_offset:
        def __get__(GitCommit self):
            cdef int offset = git_commit_time_offset(self._commit)
            return offset

    property committer:
        def __get__(GitCommit self):
            cdef GitSignature committer = GitSignature(self)
            committer._signature = git_commit_committer(self._commit)
            if committer._signature is NULL:
                return None
            return committer

    property author:
        def __get__(GitCommit self):
            cdef GitSignature author = GitSignature(self)
            author._signature = git_commit_author(self._commit)
            if author._signature is NULL:
                return None
            return author

    property tree:
        def __get__(GitCommit self):
            cdef int error
            cdef GitTree tree = GitTree()
            error = git_commit_tree(cython.address(tree._tree), self._commit)
            check_error(error)
            return tree

    property tree_id:
        def __get__(GitCommit self):
            cdef const_git_oid *oidp
            oidp = git_commit_tree_id(self._commit)
            return make_oid(self, oidp)

    property parents:
        def __get__(GitCommit self):
            cdef int error
            cdef int count
            cdef int index
            cdef GitCommit parent
            count = git_commit_parentcount(self._commit)
            if count == 0:
                return []
            parents = []
            for index from 0 <= index < count:
                parent = GitCommit()
                error = git_commit_parent(cython.address(parent._commit),
                                          self._commit, index)
                check_error(error)
                parents.append(parent)
            return parents

    property parent_ids:
        def __get__(GitCommit self):
            cdef int error
            cdef int count
            cdef int index
            cdef const_git_oid *oidp
            cdef GitOid oid
            count = git_commit_parentcount(self._commit)
            if count == 0:
                return []
            parent_ids = []
            for index from 0 <= index < count:
                oidp = git_commit_parent_id(self._commit, index)
                oid = make_oid(self, oidp)
                if oid is not None:
                    parent_ids.append(oid)
            return parent_ids


cdef class Config:

    cdef git_config *_config

    def __cinit__(Config self):
        self._config = NULL

    def __dealloc__(Config self):
        if self._config is not NULL:
            git_config_free(self._config)

    def get_entry(self, name):
        cdef bytes bname = _to_bytes(name)
        cdef int error
        cdef const_git_config_entry *entry
        error = git_config_get_entry(
            cython.address(entry), self._config, bname)
        check_error(error)
        value = <char*>entry.value
        level = entry.level
        return level, value.decode(DEFAULT_ENCODING)


cdef class GitOid:

    cdef const_git_oid *_oid

    cdef git_oid _my_oid

    cdef char *_string

    cdef readonly int length

    cdef object _owner

    def __cinit__(GitOid self):
        self._oid = NULL
        self._string = NULL
        self.length = 40
        self._owner = None

    def _dealloc__(GitOid self):
        self._oid = NULL
        self._owner = None
        if self._string is not NULL:
            stdlib.free(self._string)

    def __richcmp__(GitOid self not None, GitOid other not None, int op):
        if op == 2: # ==
            return self.hex == other.hex
        elif op == 3: # !=
            return self.hex != other.hex
        elif op == 0: # <
            return self.hex < other.hex
        elif op == 1: # <= (not >)
            return not (self.hex > other.hex)
        elif op == 4: # >
            return self.hex > other.hex
        elif op == 5: # >= (not <)
            return not (self.hex < other.hex)

    cdef object format(GitOid self):
        cdef char *hex_str = <char*>stdlib.malloc(sizeof(char)*40)
        git_oid_fmt(hex_str, self._oid)
        try:
            py_hex_str = hex_str[:40]
        finally:
            stdlib.free(hex_str)
        return py_hex_str.decode('ascii')

    @classmethod
    def from_string(cls, py_string):
        cdef int error
        cdef size_t length
        cdef GitOid oid = GitOid()

        if isinstance(py_string, unicode):
            py_string = py_string.encode('ascii')
        length = len(py_string)
        oid._string = <char*>stdlib.malloc(length)

        oid._string = py_string
        oid.length = length
        error = git_oid_fromstrn(cython.address(oid._my_oid),
                                 <const_char*>oid._string, length)
        check_error(error)
        oid._oid = <const_git_oid*>cython.address(oid._my_oid)
        return oid

    property hex:
        def __get__(GitOid self):
            return self.format()[:self.length]


cdef GitOid make_oid(object owner, const_git_oid *oidp):
    if oidp is NULL:
        return None
    cdef GitOid oid = GitOid()
    oid._owner = owner
    oid._oid = oidp
    return oid


cdef class RefLogEntry:

    cdef const_git_reflog_entry *_entry

    cdef object _reference

    def __cinit__(RefLogEntry self):
        self._entry = NULL

    def __init__(RefLogEntry self, reference):
        self._reference = reference

    property id_new:
        def __get__(RefLogEntry self):
            cdef const_git_oid *oidp
            oidp = git_reflog_entry_id_new(self._entry)
            return make_oid(self, oidp)

    property id_old:
        def __get__(RefLogEntry self):
            cdef const_git_oid *oidp
            oidp = git_reflog_entry_id_old(self._entry)
            return make_oid(self, oidp)

    property message:
        def __get__(RefLogEntry self):
            cdef char *message
            message = <char*>git_reflog_entry_message(self._entry)
            return message.decode(DEFAULT_ENCODING)


cdef class Reference:

    cdef git_reference *_reference

    def __cinit__(Reference self):
        self._reference = NULL

    def __dealloc__(Reference self):
        if self._reference is not NULL:
            git_reference_free(self._reference)

    def __richcmp__(Reference self, Reference other, int op):
        cdef int cmp_ = git_reference_cmp(self._reference, other._reference)
        if op == 2: # ==
            return cmp_ == 0
        elif op == 3: # !=
            return cmp_ != 0
        elif op == 0: # <
            return cmp_ < 0
        elif op == 1: # <=
            return cmp_ <= 0
        elif op == 4: # >
            return cmp_ > 0
        elif op == 5: # >=
            return cmp_ >= 0

    def has_log(Reference self):
        cdef int code
        code = git_reference_has_log(self._reference)
        if code == 0:
            return False
        elif code == 1:
            return True
        else:
            check_error(code)

    def logs(Reference self):
        cdef int i
        cdef int size
        cdef int error
        cdef git_reflog *reflog
        error = git_reflog_read(cython.address(reflog), self._reference)
        check_error(error)
        i = 0
        size = git_reflog_entrycount(reflog)
        try:
            while i < size:
                entry = RefLogEntry(self)
                entry._entry = git_reflog_entry_byindex(reflog, i)
                i += 1
                yield entry
        finally:
            git_reflog_free(reflog)

    def is_branch(Reference self):
        return git_reference_is_branch(self._reference) != 0

    def is_remote(Reference self):
        return git_reference_is_remote(self._reference) != 0

    property name:
        def __get__(Reference self):
            cdef bytes py_string = git_reference_name(self._reference)
            return py_string.decode(DEFAULT_ENCODING)

    property oid:
        def __get__(Reference self):
            cdef const_git_oid *oidp
            oidp = git_reference_target(self._reference)
            return make_oid(self, oidp)


cdef class GitTree:

    cdef git_tree *_tree

    def __cinit__(GitTree self):
        self._tree = NULL

    def __dealloc__(GitTree self):
        if self._tree is not NULL:
            git_tree_free(self._tree)

    def __richcmp__(GitTree self, GitTree other not None, int op):
        if op == 2: # ==
            return self.oid == other.oid
        elif op == 3: # !=
            return self.oid != other.oid
        elif op == 0: # <
            return self.oid < other.oid
        elif op == 1: # <= (not >)
            return not (self.oid > other.oid)
        elif op == 4: # >
            return self.oid > other.oid
        elif op == 5: # >= (not <)
            return not (self.oid < other.oid)

    property oid:
        def __get__(GitTree self):
            cdef const_git_oid *oidp
            oidp = git_tree_id(self._tree)
            return make_oid(self, oidp)


cdef class Repository:

    cdef git_repository *_repository

    def __cinit__(Repository self):
        self._repository = NULL

    def __dealloc__(Repository self):
        if self._repository is not NULL:
            git_repository_free(self._repository)

    def close(Repository self):
        if self._repository is not NULL:
            git_repository_free(self._repository)
            self._repository = NULL

    cdef GitOdb odb(Repository self):
        cdef int error
        cdef GitOdb odb = GitOdb()
        error = git_repository_odb(cython.address(odb._odb), self._repository)
        check_error(error)
        return odb

    @classmethod
    def open(cls, path):
        cdef bytes bpath = _to_bytes(path)
        cdef int error
        cdef Repository repo = Repository()
        error = git_repository_open(cython.address(repo._repository), bpath)
        check_error(error)
        assert_repository(repo)
        return repo

    @classmethod
    def init(cls, path, bare=False):
        cdef bytes bpath = _to_bytes(path)
        cdef int error
        cdef Repository repo = Repository()
        error = git_repository_init(cython.address(repo._repository), bpath,
                                    bare)
        check_error(error)
        assert_repository(repo)
        return repo

    @classmethod
    def clone(cls, url, path):
        cdef bytes burl = _to_bytes(url, u"ascii")
        cdef bytes bpath = _to_bytes(path)
        cdef int error
        cdef Repository repo = Repository()
        error = git_clone(cython.address(repo._repository), burl, bpath, NULL)
        check_error(error)
        assert_repository(repo)
        return repo

    def config(Repository self):
        cdef int error
        assert_repository(self)
        cdef Config conf = Config()
        error = git_repository_config(cython.address(conf._config),
                                      self._repository)
        check_error(error)
        return conf

    def lookup_ref(Repository self, name):
        cdef bytes bname = _to_bytes(name)
        if git_reference_is_valid_name(bname) == 0:
            raise LibGit2ReferenceError('Invalid reference name {!r}'.format(
                name))
        cdef int error
        cdef Reference ref = Reference()
        error = git_reference_lookup(cython.address(ref._reference),
                                     self._repository, bname)
        check_error(error)
        return ref

    def lookup_commit(Repository self, GitOid oid):
        cdef int error
        cdef GitCommit commit = GitCommit()
        error = git_commit_lookup_prefix(cython.address(commit._commit),
                                         self._repository, oid._oid, oid.length)
        check_error(error)
        return commit

    def lookup_tree(Repository self, GitOid oid):
        cdef int error
        cdef GitTree tree = GitTree()
        error = git_tree_lookup_prefix(
            cython.address(tree._tree), self._repository, oid._oid, oid.length)
        check_error(error)
        return tree

    def list_refs(Repository self):
        cdef unsigned int index
        cdef int error
        cdef git_strarray arr
        cdef bytes py_bytes
        error = git_reference_list(cython.address(arr), self._repository,
                                   GIT_REF_LISTALL)
        check_error(error)
        try:
            items = []
            for index from 0 <= index < arr.count:
                py_bytes = arr.strings[index]
                items.append(py_bytes.decode(DEFAULT_ENCODING))
            return tuple(items)
        finally:
            git_strarray_free(cython.address(arr))

    def lookup_object(Repository self, GitOid oid, EnumValue otype):
        cdef int error
        cdef git_object *_object
        cdef _GitObjectType ObjType = GitObjectType

        error = git_object_lookup_prefix(
            cython.address(_object), self._repository, oid._oid,
            oid.length, <git_otype>otype.value)
        check_error(error)

        if _object is NULL:
            return None

        cdef unsigned int t = <unsigned int>git_object_type(_object)
        type_ = ObjType._from_uint(<unsigned int>t)
        if type_ == ObjType.COMMIT:
            commit = GitCommit()
            commit._commit = <git_commit*>_object
            return commit
        elif type_ == ObjType.TREE:
            tree = GitTree()
            tree._tree = <git_tree*>_object
            return tree
        git_object_free(_object)
        return None

    def read(Repository self, GitOid oid):
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

        opts.version = GIT_STATUS_OPTIONS_VERSION
        opts.flags = 0
        opts.show = GIT_STATUS_SHOW_INDEX_THEN_WORKDIR

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
        result = {}
        error = git_status_foreach(self._repository, _status_foreach_cb,
                                   <void*>result)
        check_error(error)
        return result

    property path:
        def __get__(Repository self):
            cdef bytes py_string = git_repository_path(self._repository)
            return py_string.decode(DEFAULT_ENCODING)


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
