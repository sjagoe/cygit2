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
    GIT_OK, \
    \
    git_status_t, git_status_foreach, \
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
        result = {}
        error = git_status_foreach(self._repository, _status_foreach_cb,
                                   <void*>result)
        check_error(error)
        return result

    property path:
        def __get__(Repository self):
            return git_repository_path(self._repository)


cdef class EnumValue:

    cdef object _name
    cdef int _value

    def __init__(self, name, value):
        self._name = name
        self._value = value

    def __repr__(EnumValue self):
        return self.name

    def __or__(EnumValue self, EnumValue other):
        return CompositeEnumValue(self, other)

    def __ror__(EnumValue self, EnumValue other):
        return CompositeEnumValue(other, self)

    def __and__(EnumValue self, EnumValue other):
        return CompositeEnumValue(self) & CompositeEnumValue(other)

    def __rand__(EnumValue self, EnumValue other):
        return CompositeEnumValue(other) & CompositeEnumValue(self)

    def __richcmp__(EnumValue self, EnumValue other not None, int op):
        if op == 2: # ==
            return self.value == other.value
        elif op == 3: # !=
            return self.value != other.value
        elif op == 0: # <
            return self.value < other.value
        elif op == 1: # <= (not >)
            return not (self.value > other.value)
        elif op == 4: # >
            return self.value > other.value
        elif op == 5: # >= (not <)
            return not (self.value < other.value)

    def __hash__(EnumValue self):
        return hash((self.name, self.value))

    property name:
        def __get__(EnumValue self):
            return self._name

    property value:
        def __get__(EnumValue self):
            return self._value


cdef class CompositeEnumValue(EnumValue):

    cdef tuple _items

    def __init__(CompositeEnumValue self, *items):
        flatten = []
        for item in items:
            if isinstance(item, CompositeEnumValue):
                flatten.extend(item.items)
            elif isinstance(item, EnumValue):
                flatten.append(item)
        self._items = tuple(sorted(flatten))

    def __and__(CompositeEnumValue self, EnumValue other):
        _other = set(CompositeEnumValue(other).items)
        this = set(self.items)
        return CompositeEnumValue(*sorted(this & _other))

    property name:
        def __get__(CompositeEnumValue self):
            return ' | '.join([v.name for v in self._items])

    property value:
        def __get__(CompositeEnumValue self):
            value = 0
            for i in self.items:
                value |= i.value
            return value

    property items:
        def __get__(CompositeEnumValue self):
            return self._items


cdef EnumValue _GitStatus_from_uint(unsigned int flags):
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

    CURRENT          = EnumValue('GitStatus.CURRENT', GIT_STATUS_CURRENT)
    INDEX_NEW        = EnumValue('GitStatus.INDEX_NEW', GIT_STATUS_INDEX_NEW)
    INDEX_MODIFIED   = EnumValue('GitStatus.INDEX_MODIFIED', GIT_STATUS_INDEX_MODIFIED)
    INDEX_DELETED    = EnumValue('GitStatus.INDEX_DELETED', GIT_STATUS_INDEX_DELETED)
    INDEX_RENAMED    = EnumValue('GitStatus.INDEX_RENAMED', GIT_STATUS_INDEX_RENAMED)
    INDEX_TYPECHANGE = EnumValue('GitStatus.INDEX_TYPECHANGE', GIT_STATUS_INDEX_TYPECHANGE)
    WT_NEW           = EnumValue('GitStatus.WT_NEW', GIT_STATUS_WT_NEW)
    WT_MODIFIED      = EnumValue('GitStatus.WT_MODIFIED', GIT_STATUS_WT_MODIFIED)
    WT_DELETED       = EnumValue('GitStatus.WT_DELETED', GIT_STATUS_WT_DELETED)
    WT_TYPECHANGE    = EnumValue('GitStatus.WT_TYPECHANGE', GIT_STATUS_WT_TYPECHANGE)
    IGNORED          = EnumValue('GitStatus.IGNORED', GIT_STATUS_IGNORED)

    cdef EnumValue _flags

    @classmethod
    def _from_uint(cls, unsigned int flags):
        return _GitStatus_from_uint(flags)

    cpdef unsigned int _to_uint(GitStatus self):
        return self._flags.value

    def __init__(GitStatus self, EnumValue flags):
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


cdef int _status_foreach_cb(const_char_ptr path,
                            unsigned int flags, void *payload):
    result = <object>payload
    py_path = <char*>path
    result[py_path] = GitStatus(_GitStatus_from_uint(flags))
    return GIT_OK
