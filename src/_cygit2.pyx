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
import os

from libc cimport stdlib
from libc.stdint cimport int64_t

import cython

from libc.string cimport const_char, const_uchar

from _types cimport \
    const_git_signature, \
    git_blob, \
    git_signature, \
    git_commit, \
    git_config, \
    git_object, \
    git_odb, \
    git_repository, \
    git_time_t, \
    git_reference, \
    git_ref_t, \
    git_reflog, \
    const_git_reflog_entry, \
    git_tree, \
    git_tree_entry, \
    const_git_tree_entry, \
    git_otype, \
    git_off_t, \
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
    GIT_REF_INVALID, \
    GIT_REF_OID, \
    GIT_REF_SYMBOLIC, \
    GIT_REF_LISTALL, \
    GIT_PATH_MAX, \
    MAXPATHLEN

from _strarray cimport git_strarray, git_strarray_free

from _repository cimport \
    git_repository_odb, git_repository_open, git_repository_path, \
    git_repository_init, git_repository_free, git_repository_config, \
    git_repository_head, git_repository_discover, git_repository_head_orphan, \
    git_repository_head_detached, git_repository_is_bare, \
    git_repository_is_empty, git_repository_workdir

from _revparse cimport git_revparse_single

from _odb cimport \
    git_odb_read_prefix, git_odb_free, git_odb_foreach, git_odb_hash, \
    git_odb_hashfile, git_odb_object, git_odb_object_free, git_odb_object_id, \
    git_odb_object_data, git_odb_object_size, git_odb_object_type

from _commit cimport \
    git_commit_free, git_commit_lookup_prefix, git_commit_id, \
    git_commit_message_encoding, git_commit_message, git_commit_time, \
    git_commit_time_offset, git_commit_committer, git_commit_author, \
    git_commit_tree, git_commit_tree_id, git_commit_parentcount, \
    git_commit_parent, git_commit_parent_id, git_commit_nth_gen_ancestor

from _signature cimport \
    git_signature_free, git_signature_new, git_signature_now

from _config cimport \
    git_config_new, git_config_free, git_config_open_ondisk, \
    git_config_add_file_ondisk, const_git_config_entry, git_config_get_entry, \
    git_config_get_int64, git_config_get_bool, git_config_get_string, \
    git_config_get_multivar, git_config_foreach, git_config_find_global, \
    git_config_find_system

from _oid cimport \
    git_oid, const_git_oid, git_oid_fmt, git_oid_fromstrn, git_oid_fromraw, \
    GIT_OID_MINPREFIXLEN, GIT_OID_RAWSZ, GIT_OID_HEXSZ

from _refs cimport \
    git_reference_free, git_reference_lookup, \
    git_reference_name, git_reference_target, git_reference_cmp, \
    git_reference_has_log, git_reference_list, git_reference_is_valid_name, \
    git_reference_is_branch, git_reference_is_remote, git_reference_type, \
    git_reference_symbolic_target, git_reference_resolve

from _reflog cimport \
    git_reflog_free, git_reflog_read, git_reflog_entrycount, \
    git_reflog_entry_byindex, git_reflog_entry_id_new, \
    git_reflog_entry_id_old, git_reflog_entry_message

from _tree cimport \
    git_tree_free, git_tree_lookup_prefix, git_tree_id, \
    git_tree_entry_bypath, git_tree_entry_byindex, git_tree_entrycount, \
    git_tree_entry_id, git_tree_entry_dup, git_tree_entry_free, \
    git_tree_entry_name, git_tree_entry_byname, git_tree_entry_filemode, \
    git_tree_entry_to_object

from _blob cimport \
    git_blob_free, \
    git_blob_id, \
    git_blob_rawcontent, \
    git_blob_rawsize, \
    git_blob_create_frombuffer, \
    git_blob_create_fromworkdir

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

from _clone cimport git_clone

from _object cimport \
    git_object_lookup_prefix, \
    git_object_free, \
    git_object_type


include "_encoding.pxi"
include "_error.pxi"
include "_enum.pxi"


@cython.internal
cdef class _GitReferenceType:

    cdef readonly EnumValue INVALID
    cdef readonly EnumValue OID
    cdef readonly EnumValue SYMBOLIC
    cdef readonly EnumValue LISTALL

    def __init__(_GitReferenceType self):
        self.INVALID  = EnumValue('GitReferenceType.INVALID', GIT_REF_INVALID)
        self.OID      = EnumValue('GitReferenceType.OID', GIT_REF_OID)
        self.SYMBOLIC = EnumValue('GitReferenceType.SYMBOLIC', GIT_REF_SYMBOLIC)
        self.LISTALL  = EnumValue('GitReferenceType.LISTALL', GIT_REF_LISTALL)

    cdef _from_git_ref_t(_GitReferenceType self, git_ref_t type_):
        for item in (self.INVALID,
                     self.OID,
                     self.SYMBOLIC,
                     self.LISTALL):
            if type_ == item.value:
                return item
        raise LibGit2Error('Invalid GitReferenceType: {!r}'.format(type_))


GitReferenceType = _GitReferenceType()


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

    cdef _compare_type_contents(GitOdbObject self,
                                EnumValue other_type, other_contents,
                                int op):
        if op == 2: # ==
            return self.type == other_type and self.data == other_contents
        elif op == 3: # !=
            return not (self.type == other_type and self.data == other_contents)
        elif op == 0: # <
            return self.type < other_type and self.data < other_contents
        elif op == 1: # <= (not >)
            return not (self.type > other_type and self.data > other_contents)
        elif op == 4: # >
            return self.type > other_type and self.data > other_contents
        elif op == 5: # >= (not <)
            return not (self.type < other_type and self.data < other_contents)

    def __richcmp__(GitOdbObject self, other, int op):
        cdef bytes other_contents
        cdef EnumValue other_type
        if isinstance(other, tuple):
            other_type = other[0]
            if isinstance(other[1], unicode):
                other_contents = other[1].encode(DEFAULT_ENCODING)
            else:
                other_contents = other[1]
            return self._compare_type_contents(other_type, other_contents, op)
        if not isinstance(other, GitOdbObject):
            return False
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


cdef int _GitOdb_get_oids(const_git_oid *oid, void *payload):
    cdef tuple py_payload = <object>payload
    owner, result = py_payload
    result.append(make_oid(owner, oid))
    return 0


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
        assert_GitOid(oid)
        error = git_odb_read_prefix(cython.address(obj._object), self._odb,
                                    oid._oid, oid.length)
        check_error(error)
        return obj

    cdef oids(GitOdb self):
        cdef int error
        cdef object payload = (self, [])
        error = git_odb_foreach(self._odb, _GitOdb_get_oids, <void*>payload)
        return payload[1]


cdef class GitSignature:

    cdef git_signature *_signature

    cdef object _owner

    cdef readonly unicode _encoding

    def __cinit__(GitSignature self):
        self._signature = NULL
        self._owner = None

    def __init__(GitSignature self, name=None, email=None, time=None,
                 offset=None, encoding=None):
        cdef int error
        cdef bytes bytes_name
        cdef bytes bemail
        cdef char *c_name = NULL
        cdef char *c_email = NULL
        cdef git_time_t c_time = -1
        cdef int c_offset = 0

        if name is None or email is None:
            self._encoding = DEFAULT_ENCODING
            return # Fixme

        if encoding is not None:
            encoding = encoding[:len(encoding)]
        else:
            encoding = u'ascii'

        if name is not None:
            bytes_name = _to_bytes(name, encoding)
            c_name = bytes_name
        if email is not None:
            bemail = _to_bytes(email, encoding)
            c_email = bemail
        if time is not None:
            c_time = time
        if offset is not None:
            c_offset = offset

        if c_time != -1:
            error = git_signature_new(cython.address(self._signature), c_name,
                                      c_email, c_time, c_offset)
        else:
            error = git_signature_now(cython.address(self._signature), c_name,
                                      c_email)
        check_error(error)

        self._encoding = encoding

    def __dealloc__(GitSignature self):
        if self._signature is not NULL and self._owner is None:
            git_signature_free(self._signature)

    property _name:
        def __get__(GitSignature self):
            cdef bytes py_string = self._signature.name
            return py_string

    property name:
        def __get__(GitSignature self):
            return self._name.decode(self._encoding)

    property email:
        def __get__(GitSignature self):
            cdef bytes py_string = self._signature.email
            return py_string.decode(self._encoding)

    property time:
        def __get__(GitSignature self):
            cdef git_time_t time = self._signature.when.time
            return time

    property offset:
        def __get__(GitSignature self):
            cdef int time = self._signature.when.offset
            return time


cdef GitSignature _make_signature(const_git_signature *_signature, object owner):
    if _signature is NULL:
        return None
    # FIXME: Inefficient
    cdef GitSignature signature = GitSignature()
    # git_signature_free(signature._signature)
    signature._signature = NULL
    signature._owner = owner
    signature._signature = <git_signature*>_signature
    return signature


cdef _GitObject_from_git_object_pointer(Repository repo, git_object *_object):
    cdef _GitObjectType ObjType = GitObjectType
    if _object is NULL:
        return None

    cdef unsigned int t = <unsigned int>git_object_type(_object)
    type_ = ObjType._from_uint(<unsigned int>t)
    if type_ == ObjType.COMMIT:
        commit = GitCommit(repo)
        commit._object = _object
        return commit
    elif type_ == ObjType.TREE:
        tree = GitTree(repo)
        tree._object = _object
        return tree
    elif type_ == ObjType.BLOB:
        blob = GitBlob(repo)
        blob._object = _object
        return blob
    git_object_free(_object)
    raise TypeError('Unsupported object type {!r}'.format(type_))


cdef class GitObject:

    cdef git_object *_object

    cdef Repository _repository

    def __cinit__(GitObject self):
        self._object = NULL

    def __init__(self, Repository repo):
        self._repository = repo

    property type:
        def __get__(GitCommit self):
            cdef _GitObjectType ObjType = GitObjectType
            return ObjType._from_uint(git_object_type(self._object))

    property hex:
        def __get__(GitCommit self):
            return self.oid.hex


cdef class GitCommit(GitObject):

    def __dealloc__(GitCommit self):
        if self._object is not NULL:
            git_commit_free(<git_commit*>self._object)

    cdef object _get_message(GitCommit self):
        cdef bytes py_string
        cdef const_char *message = git_commit_message(<git_commit*>self._object)
        if message is NULL:
            return None
        py_string = <char*>message
        return py_string

    def ancestor(GitCommit self, unsigned int generation):
        cdef int error
        cdef GitCommit parent = GitCommit()
        error = git_commit_nth_gen_ancestor(<git_commit**>cython.address(parent._object),
                                            <git_commit*>self._object, generation)
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
            oidp = git_commit_id(<git_commit*>self._object)
            return make_oid(self, oidp)

    property message_encoding:
        def __get__(GitCommit self):
            cdef bytes py_string
            cdef const_char *encoding = git_commit_message_encoding(<git_commit*>self._object)
            if encoding is NULL:
                return None
            py_string = <char*>encoding
            return py_string.decode('ascii') # Will it always be ascii?

    property message:
        def __get__(GitCommit self):
            message = self._get_message()
            if message is None:
                return None
            encoding = self.message_encoding
            if encoding is None:
                encoding = DEFAULT_ENCODING
            return message.decode(encoding)

    property _message:
        def __get__(GitCommit self):
            return self._get_message()

    # FIXME: Convert time and time_offset into datetime
    property commit_time:
        def __get__(GitCommit self):
            cdef git_time_t time = git_commit_time(<git_commit*>self._object)
            cdef object py_time = time
            return py_time

    property time_offset:
        def __get__(GitCommit self):
            cdef int offset = git_commit_time_offset(<git_commit*>self._object)
            return offset

    property committer:
        def __get__(GitCommit self):
            cdef const_git_signature *sig = git_commit_committer(<git_commit*>self._object)
            return _make_signature(sig, self)

    property author:
        def __get__(GitCommit self):
            cdef const_git_signature *sig = git_commit_author(<git_commit*>self._object)
            return _make_signature(sig, self)

    property tree:
        def __get__(GitCommit self):
            cdef int error
            cdef GitTree tree = GitTree(self._repository)
            error = git_commit_tree(<git_tree**>cython.address(tree._object),
                                    <git_commit*>self._object)
            check_error(error)
            return tree

    property tree_id:
        def __get__(GitCommit self):
            cdef const_git_oid *oidp
            oidp = git_commit_tree_id(<git_commit*>self._object)
            return make_oid(self, oidp)

    property parents:
        def __get__(GitCommit self):
            cdef int error
            cdef int count
            cdef int index
            cdef GitCommit parent
            count = git_commit_parentcount(<git_commit*>self._object)
            if count == 0:
                return []
            parents = []
            for index from 0 <= index < count:
                parent = GitCommit(self._repository)
                error = git_commit_parent(<git_commit**>cython.address(parent._object),
                                          <git_commit*>self._object, index)
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
            count = git_commit_parentcount(<git_commit*>self._object)
            if count == 0:
                return []
            parent_ids = []
            for index from 0 <= index < count:
                oidp = git_commit_parent_id(<git_commit*>self._object, index)
                oid = make_oid(self, oidp)
                if oid is not None:
                    parent_ids.append(oid)
            return parent_ids


cdef class GitBlob(GitObject):

    def __dealloc__(GitBlob self):
        if self._object is not NULL:
            git_blob_free(<git_blob*>self._object)

    cpdef read_raw(GitBlob self):
        cdef bytes py_content
        cdef char *content = <char*>git_blob_rawcontent(<git_blob*>self._object)
        py_content = content
        return py_content

    property oid:
        def __get__(GitBlob self):
            cdef const_git_oid *oidp
            oidp = git_blob_id(<git_blob*>self._object)
            return make_oid(self, oidp)

    property data:
        def __get__(GitBlob self):
            return self.read_raw()

    property size:
        def __get__(GitBlob self):
            cdef git_off_t size = git_blob_rawsize(<git_blob*>self._object)
            return int(size)


class GitItemNotFound(Exception): pass


cdef object _get_config_entry(git_config *config, name):
    cdef int error
    cdef int64_t c_int
    cdef int c_bool
    cdef char *c_string
    cdef bytes py_string
    cdef bytes bname = _to_bytes(name)

    error = git_config_get_int64(
        cython.address(c_int), config, bname)
    if error == GIT_OK:
        return c_int

    error = git_config_get_bool(
        cython.address(c_bool), config, bname)
    if error == GIT_OK:
        return bool(c_bool)

    error = git_config_get_string(
        <const_char**>cython.address(c_string), config, bname)
    if error == GIT_OK:
        py_string = c_string
        return py_string.decode(DEFAULT_ENCODING)

    if error == GIT_ENOTFOUND:
        raise GitItemNotFound()
    check_error(error)


cdef int _git_config_get_multivar_cb(const_git_config_entry *entry,
                                     void *payload):
    cdef list result = <object>payload
    if entry is NULL or entry.value is NULL:
        return GIT_ENOTFOUND
    value = <char*>entry.value
    result.append(value.decode(DEFAULT_ENCODING))
    return 0


cdef int _git_config_foreach_callback(const_git_config_entry *entry,
                                      void *c_payload):
    cdef bytes entry_name
    cdef bytes entry_value
    cdef object py_callback
    cdef object py_payload
    cdef tuple payload = <object>c_payload
    py_callback, py_payload = payload
    entry_name = entry.name
    # FIXME?
    entry_value = entry.value

    if py_payload is None:
        py_callback(entry_name.decode(DEFAULT_ENCODING), entry.value)
    else:
        py_callback(entry_name.decode(DEFAULT_ENCODING), entry.value, py_payload)
    return 0


def _Config_get_global_config():
    cdef int error
    cdef bytes py_path
    cdef char *path = <char*>stdlib.malloc(GIT_PATH_MAX+1)
    try:
        path[GIT_PATH_MAX] = '\0'
        error = git_config_find_global(path, GIT_PATH_MAX)
        if error == GIT_ENOTFOUND:
            return Config()
        check_error(error)
        py_path = path
        return Config(py_path)
    finally:
        stdlib.free(path)


def _Config_get_system_config():
    cdef int error
    cdef bytes py_path
    cdef char *path = <char*>stdlib.malloc(GIT_PATH_MAX)
    try:
        error = git_config_find_system(path, GIT_PATH_MAX)
        try:
            check_error(error)
        except LibGit2OSError as e:
            raise IOError(unicode(e))
        py_path = path
        return Config(py_path)
    finally:
        stdlib.free(path)


cdef class Config:

    cdef git_config *_config

    def __cinit__(Config self):
        self._config = NULL

    def __init__(Config self, filename=None):
        cdef int error
        cdef bytes c_filename
        if filename is not None:
            c_filename = _to_bytes(filename)
            error = git_config_open_ondisk(cython.address(self._config),
                                           c_filename)
        else:
            error = git_config_new(cython.address(self._config))
        check_error(error)

    def __dealloc__(Config self):
        if self._config is not NULL:
            git_config_free(self._config)

    get_global_config = staticmethod(_Config_get_global_config)

    get_system_config = staticmethod(_Config_get_system_config)

    def add_file(Config self, path, level=0, force=0):
        cdef int error
        cdef bytes c_path = _to_bytes(path)
        cdef unsigned int c_level = level
        cdef int c_force = force
        error = git_config_add_file_ondisk(self._config, c_path, c_level,
                                           c_force)
        check_error(error)

    def get_multivar(Config self, path, regexp=None):
        cdef int error
        cdef bytes py_regexp
        cdef const_char *c_regexp = NULL
        cdef bytes py_string = _to_bytes(path)
        cdef const_char *c_string = py_string
        if regexp is not None:
            py_regexp = _to_bytes(regexp)
            c_regexp = py_regexp
        result = []
        error = git_config_get_multivar(
            self._config, c_string, c_regexp,
            _git_config_get_multivar_cb, <void*>result)
        check_error(error)
        return result

    def foreach(Config self, object callback, object py_payload=None):
        cdef int error
        cdef tuple payload = (callback, py_payload)
        error = git_config_foreach(
            self._config, _git_config_foreach_callback, <void*>payload)
        check_error(error)

    cdef get_entry(Config self, name):
        cdef bytes bname = _to_bytes(name)
        cdef int error
        cdef const_git_config_entry *entry
        error = git_config_get_entry(
            cython.address(entry), self._config, bname)
        check_error(error)
        value = <char*>entry.value
        level = entry.level
        return level, value.decode(DEFAULT_ENCODING)

    cdef get_value(Config self, name):
        try:
            return _get_config_entry(self._config, name)
        except GitItemNotFound:
            raise KeyError(name)
        except LibGit2Error as e:
            raise ValueError(e.args[0].decode(DEFAULT_ENCODING))

    cdef _check_name(Config self, name):
        if not isinstance(name, (bytes, str, unicode)):
            raise TypeError(type(name))

    def __getitem__(Config self, name):
        self._check_name(name)
        return self.get_value(name)

    def __contains__(Config self, name):
        self._check_name(name)
        return self.get_entry(name) is not None # FIXME


cdef GitOid _empty_GitOid():
    cdef GitOid empty = GitOid.__new__(GitOid)
    empty._oid = <const_git_oid*>cython.address(empty._my_oid)
    return empty


cdef class GitOid:

    cdef const_git_oid *_oid

    cdef git_oid _my_oid

    cdef readonly int length

    cdef object _owner

    def __cinit__(GitOid self):
        self._oid = NULL
        self.length = GIT_OID_HEXSZ
        self._owner = None

    def __init__(GitOid self, hex=None, raw=None):
        if raw is not None and hex is not None:
            raise ValueError()
        elif raw is None and hex is None:
            raise ValueError()

        # FIXME: Check raw min length
        if hex is not None and len(hex) < GIT_OID_MINPREFIXLEN:
            raise ValueError(('OID is shorted than minimum length ({}): '
                              '{!r}').format(GIT_OID_MINPREFIXLEN, hex))
        elif hex is not None and len(hex) > GIT_OID_HEXSZ:
            raise ValueError('Length of hex OID is larger than {}: {!r}'.format(
                GIT_OID_RAWSZ, hex))
        elif raw is not None and len(raw) > GIT_OID_RAWSZ:
            raise ValueError('Length of raw OID is larger than {}: {!r}'.format(
                GIT_OID_RAWSZ, raw))
        elif raw is not None and not isinstance(raw, bytes):
            raise ValueError('Raw value should be {}, got {} instead'.format(
                bytes, type(raw)))

        cdef int error
        cdef size_t length
        cdef char *c_string

        self._oid = <const_git_oid*>cython.address(self._my_oid)
        if hex is not None:
            if isinstance(hex, unicode):
                hex = hex.encode('ascii')
            length = len(hex)
            c_string = hex
            error = git_oid_fromstrn(cython.address(self._my_oid),
                                     <const_char*>c_string, length)
            check_error(error)
            self.length = length
        elif raw is not None:
            c_string = raw
            git_oid_fromraw(cython.address(self._my_oid),
                            <const_uchar*>c_string)

    def _dealloc__(GitOid self):
        self._oid = NULL
        self._owner = None

    def __hash__(self):
        hash(self.raw)

    def __len__(self):
        return self.length

    def __richcmp__(GitOid self not None, other, int op):
        if isinstance(other, GitOid):
            other_hex = other.hex
        else:
            other_hex = other
        if op == 2: # ==
            return self.hex == other_hex
        elif op == 3: # !=
            return self.hex != other_hex
        elif op == 0: # <
            return self.hex < other_hex
        elif op == 1: # <= (not >)
            return not (self.hex > other_hex)
        elif op == 4: # >
            return self.hex > other_hex
        elif op == 5: # >= (not <)
            return not (self.hex < other_hex)

    cdef object format(GitOid self):
        assert_GitOid(self)
        cdef char *hex_str = <char*>stdlib.malloc(GIT_OID_HEXSZ)
        git_oid_fmt(hex_str, self._oid)
        try:
            py_hex_str = hex_str[:GIT_OID_HEXSZ]
        finally:
            stdlib.free(hex_str)
        return py_hex_str.decode('ascii')

    property hex:
        def __get__(GitOid self):
            assert_GitOid(self)
            return self.format()[:self.length]

    property raw:
        def __get__(GitOid self):
            assert_GitOid(self)
            cdef unsigned char *string = self._oid.id
            cdef bytes py_string = string[:GIT_OID_RAWSZ]
            return py_string

    def __repr__(GitOid self):
        return 'GitOid({!r})'.format(self.hex)


cdef GitOid make_oid(object owner, const_git_oid *oidp):
    if oidp is NULL:
        return None
    cdef GitOid oid = _empty_GitOid()
    oid._owner = owner
    oid._oid = oidp
    assert_GitOid(oid)
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

    cdef git_ref_t _type(Reference self):
        return git_reference_type(self._reference)

    def resolve(Reference self):
        cdef int error
        cdef git_ref_t type_ = self._type()
        if type_ == GIT_REF_OID:
            return self
        if type_ == GIT_REF_SYMBOLIC:
            ref = Reference()
            error = git_reference_resolve(cython.address(ref._reference),
                                          self._reference)
            check_error(error)
            return ref

    property name:
        def __get__(Reference self):
            cdef bytes py_string = git_reference_name(self._reference)
            return py_string.decode(DEFAULT_ENCODING)

    property target:
        def __get__(Reference self):
            cdef const_git_oid *oidp
            cdef bytes py_string
            cdef git_ref_t type_ = git_reference_type(self._reference)
            if type_ == GIT_REF_OID:
                oidp = git_reference_target(self._reference)
                return make_oid(self, oidp)
            elif type_ == GIT_REF_SYMBOLIC:
                py_string = git_reference_symbolic_target(
                    self._reference)
                return py_string.decode(DEFAULT_ENCODING)

    property oid:
        def __get__(Reference self):
            cdef const_git_oid *oidp
            oidp = git_reference_target(self._reference)
            return make_oid(self, oidp)

    property hex:
        def __get__(Reference self):
            return self.oid.hex

    property type:
        def __get__(Reference self):
            cdef _GitReferenceType RefType = GitReferenceType
            cdef git_ref_t type_ = self._type()
            return RefType._from_git_ref_t(type_)


cdef class GitTreeEntry:

    cdef git_tree_entry *_entry

    cdef Repository _repository

    def __cinit__(GitTreeEntry self):
        self._entry = NULL

    def __init__(self, Repository repo):
        self._repository = repo

    def __dealloc__(GitTreeEntry self):
        if self._entry is not NULL:
            git_tree_entry_free(self._entry)

    property name:
        def __get__(GitTreeEntry self):
            cdef const_char *path = git_tree_entry_name(self._entry)
            cdef bytes py_path = path
            return py_path.decode(DEFAULT_ENCODING)

    property oid:
        def __get__(GitTreeEntry self):
            cdef const_git_oid *oidp
            oidp = git_tree_entry_id(self._entry)
            return make_oid(self, oidp)

    property hex:
        def __get__(self):
            return self.oid.hex

    property filemode:
        def __get__(self):
            return long(git_tree_entry_filemode(self._entry))

    def to_object(self):
        cdef int error
        cdef git_object *_object
        error = git_tree_entry_to_object(cython.address(_object),
                                         self._repository._repository,
                                         self._entry)
        check_error(error)
        return _GitObject_from_git_object_pointer(self._repository, _object)


cdef class GitTree(GitObject):

    def __dealloc__(GitTree self):
        if self._object is not NULL:
            git_tree_free(<git_tree*>self._object)

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
            oidp = git_tree_id(<git_tree*>self._object)
            return make_oid(self, oidp)

    cdef size_t _len(GitTree self):
        return git_tree_entrycount(<git_tree*>self._object)

    def __len__(GitTree self):
        len_ = self._len()
        return len_

    cdef _item_by_index(GitTree self, index):
        cdef long index_ = index
        cdef size_t len_ = self._len()
        cdef long llen = <long>len_
        if index_ >= llen:
            raise IndexError(index)
        elif index_ < -llen:
            raise IndexError(index)
        if index_ < 0:
            index_ = len_ + index_

        entry = GitTreeEntry(self._repository)
        entry._entry = git_tree_entry_dup(
            git_tree_entry_byindex(<git_tree*>self._object, index_))
        return entry

    cdef _item_by_path(GitTree self, path):
        cdef int error
        cdef bytes bpath = _to_bytes(path)

        entry = GitTreeEntry(self._repository)
        error = git_tree_entry_bypath(cython.address(entry._entry),
                                      <git_tree*>self._object, bpath)
        if error != GIT_OK:
            raise KeyError(path)
        return entry

    def __getitem__(GitTree self, value):
        if isinstance(value, int) or isinstance(value, long):
            return self._item_by_index(value)
        elif isinstance(value, bytes) or isinstance(value, unicode):
            return self._item_by_path(value)
        else:
            raise TypeError('Unexpected {}'.format(type(value)))

    def __contains__(GitTree self, filename):
        """Returns True if the item specified by ``filename`` is in the tree.

        """
        cdef bytes bpath = _to_bytes(filename)
        cdef const_git_tree_entry *entry = git_tree_entry_byname(
            <git_tree*>self._object, bpath)
        if entry is NULL:
            return False
        return True


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
