from libc cimport stdlib

import cython

from _types cimport const_char_ptr

from _git2 cimport \
    \
    git_repository, git_repository_open, git_repository_path, \
    git_repository_init, git_repository_free, git_repository_config, \
    \
    git_config, git_config_free, \
    const_git_config_entry, git_config_get_entry, \
    \
    git_strarray, git_strarray_free, \
    \
    const_git_oid, git_oid_fmt, \
    \
    git_reference, git_reference_free, git_reference_lookup, \
    git_reference_name, git_reference_target, git_reference_reload, \
    git_reference_cmp, git_reference_has_log, git_reference_list, \
    git_reference_is_valid_name, git_reference_is_branch, \
    git_reference_is_packed, git_reference_is_remote, \
    GIT_REF_LISTALL, \
    \
    git_reflog, git_reflog_free, git_reflog_read, git_reflog_entrycount, \
    const_git_reflog_entry, git_reflog_entry_byindex, git_reflog_entry_id_new, \
    git_reflog_entry_id_old, git_reflog_entry_message, \
    \
    GIT_OK, git_status_foreach, \
    \
    git_clone, \
    \
    const_git_error, giterr_last, \
    GITERR_NOMEMORY, \
    GITERR_OS, \
    GITERR_INVALID, \
    GITERR_REFERENCE, \
    GITERR_ZLIB, \
    GITERR_REPOSITORY, \
    GITERR_CONFIG, \
    GITERR_REGEX, \
    GITERR_ODB, \
    GITERR_INDEX, \
    GITERR_OBJECT, \
    GITERR_NET, \
    GITERR_TAG, \
    GITERR_TREE, \
    GITERR_INDEXER, \
    GITERR_SSL, \
    GITERR_SUBMODULE, \
    GITERR_THREAD, \
    GITERR_STASH, \
    GITERR_CHECKOUT, \
    GITERR_FETCHHEAD, \
    GITERR_MERGE


class LibGit2Error(Exception): pass
class LibGit2NoMemoryError(LibGit2Error): pass
class LibGit2OSError(LibGit2Error): pass
class LibGit2InvalidError(LibGit2Error): pass
class LibGit2ReferenceError(LibGit2Error): pass
class LibGit2ZLibError(LibGit2Error): pass
class LibGit2RepositoryError(LibGit2Error): pass
class LibGit2ConfigError(LibGit2Error): pass
class LibGit2RegexError(LibGit2Error): pass
class LibGit2ODBError(LibGit2Error): pass
class LibGit2IndexError(LibGit2Error): pass
class LibGit2ObjectError(LibGit2Error): pass
class LibGit2NetError(LibGit2Error): pass
class LibGit2TagError(LibGit2Error): pass
class LibGit2TreeError(LibGit2Error): pass
class LibGit2IndexerError(LibGit2Error): pass
class LibGit2SSLError(LibGit2Error): pass
class LibGit2SubmoduleError(LibGit2Error): pass
class LibGit2ThreadError(LibGit2Error): pass
class LibGit2StashError(LibGit2Error): pass
class LibGit2CheckoutError(LibGit2Error): pass
class LibGit2FetchHeadError(LibGit2Error): pass
class LibGit2MergeError(LibGit2Error): pass


ERRORS = {
    GITERR_NOMEMORY: LibGit2NoMemoryError,
    GITERR_OS: LibGit2OSError,
    GITERR_INVALID: LibGit2InvalidError,
    GITERR_REFERENCE: LibGit2ReferenceError,
    GITERR_ZLIB: LibGit2ZLibError,
    GITERR_REPOSITORY: LibGit2RepositoryError,
    GITERR_CONFIG: LibGit2ConfigError,
    GITERR_REGEX: LibGit2RegexError,
    GITERR_ODB: LibGit2ODBError,
    GITERR_INDEX: LibGit2IndexError,
    GITERR_OBJECT: LibGit2ObjectError,
    GITERR_NET: LibGit2NetError,
    GITERR_TAG: LibGit2TagError,
    GITERR_TREE: LibGit2TreeError,
    GITERR_INDEXER: LibGit2IndexerError,
    GITERR_SSL: LibGit2SSLError,
    GITERR_SUBMODULE: LibGit2SubmoduleError,
    GITERR_THREAD: LibGit2ThreadError,
    GITERR_STASH: LibGit2StashError,
    GITERR_CHECKOUT: LibGit2CheckoutError,
    GITERR_FETCHHEAD: LibGit2FetchHeadError,
    GITERR_MERGE: LibGit2MergeError,
}


cdef assert_repository(Repository repo):
    if repo._repository is NULL:
        raise LibGit2Error('Invalid Repository')


cdef check_error(int error):
    cdef const_git_error *err
    if error != GIT_OK:
        err = giterr_last()
        if err is not NULL and err.klass in ERRORS:
            raise ERRORS[err.klass](err.message)
        else:
            raise LibGit2Error('Unknown error')


cdef class Config:

    cdef git_config *_config

    def __cinit__(Config self):
        self._config = NULL

    def __dealloc__(Config self):
        if self._config is not NULL:
            git_config_free(self._config)

    def get_entry(self, name):
        cdef int error
        cdef const_git_config_entry *entry
        error = git_config_get_entry(
            cython.address(entry), self._config, name)
        check_error(error)
        value = <char*>entry.value
        level = entry.level
        return level, value


cdef class GitOid:

    cdef const_git_oid *_oid

    cdef object _owner

    def __cinit__(GitOid self):
        self._oid = NULL

    def __init__(GitOid self, owner):
        self._owner = owner

    def format(GitOid self):
        cdef char *hex_str = <char*>stdlib.malloc(sizeof(char)*40)
        git_oid_fmt(hex_str, self._oid)
        try:
            py_hex_str = hex_str[:40]
        finally:
            stdlib.free(hex_str)
        return py_hex_str.decode('ascii')


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
            if oidp is NULL:
                return None

            oid = GitOid(self)
            oid._oid = oidp

            return oid

    property id_old:
        def __get__(RefLogEntry self):
            cdef const_git_oid *oidp

            oidp = git_reflog_entry_id_old(self._entry)
            if oidp is NULL:
                return None

            oid = GitOid(self)
            oid._oid = oidp

            return oid

    property message:
        def __get__(RefLogEntry self):
            cdef char *message
            message = <char*>git_reflog_entry_message(self._entry)
            return message.decode('utf-8')


cdef class Reference:

    cdef git_reference *_reference

    def __cinit__(Reference self):
        self._reference = NULL

    def __dealloc__(Reference self):
        if self._reference is not NULL:
            git_reference_free(self._reference)

    def __cmp__(Reference self, Reference other):
        return git_reference_cmp(self._reference, other._reference)

    def reload(Reference self):
        cdef int error
        error = git_reference_reload(self._reference)
        if error != GIT_OK:
            self._reference = NULL
        check_error(error)

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

    def is_packed(Reference self):
        return git_reference_is_packed(self._reference) != 0

    def is_remote(Reference self):
        return git_reference_is_remote(self._reference) != 0

    property name:
        def __get__(Reference self):
            return git_reference_name(self._reference)

    property oid:
        def __get__(Reference self):
            cdef const_git_oid *oidp
            oidp = git_reference_target(self._reference)
            if oidp is NULL:
                return None
            oid = GitOid(self)
            oid._oid = oidp
            return oid


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

    @classmethod
    def open(cls, path):
        cdef int error
        repo = Repository()
        error = git_repository_open(cython.address(repo._repository), path)
        check_error(error)
        assert_repository(repo)
        return repo

    @classmethod
    def init(cls, path, bare=False):
        cdef int error
        repo = Repository()
        error = git_repository_init(cython.address(repo._repository), path, bare)
        check_error(error)
        assert_repository(repo)
        return repo

    @classmethod
    def clone(cls, url, path):
        cdef int error
        repo = Repository()
        error = git_clone(cython.address(repo._repository), url, path, NULL)
        check_error(error)
        assert_repository(repo)
        return repo

    def config(Repository self):
        cdef int error
        assert_repository(self)
        conf = Config()
        error = git_repository_config(cython.address(conf._config),
                                      self._repository)
        check_error(error)
        return conf

    def lookup_ref(Repository self, name):
        if git_reference_is_valid_name(name) == 0:
            raise LibGit2ReferenceError('Invalid reference name {!r}'.format(
                name))
        cdef int error
        ref = Reference()
        error = git_reference_lookup(cython.address(ref._reference),
                                     self._repository, name)
        check_error(error)
        return ref

    def list_refs(Repository self):
        cdef int error
        cdef git_strarray arr
        error = git_reference_list(cython.address(arr), self._repository,
                                   GIT_REF_LISTALL)
        check_error(error)
        try:
            return tuple(arr.strings[index] for index in xrange(arr.count))
        finally:
            git_strarray_free(cython.address(arr))

    def status(Repository self):
        cdef int error
        error = git_status_foreach(self._repository, _status_foreach_cb, NULL)
        check_error(error)
        return None

    property path:
        def __get__(Repository self):
            return git_repository_path(self._repository)

cdef int _status_foreach_cb(const_char_ptr path,
                            unsigned int flags, void *payload):
    print <char*>path
    return GIT_OK
