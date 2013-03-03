import cython

from _git2 cimport \
    \
    git_repository, git_repository_open, git_repository_path, \
    git_repository_init, git_repository_free, git_repository_config, \
    \
    git_config, git_config_free, \
    const_git_config_entry, git_config_get_entry, \
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
    cdef const_git_error* err
    if error != 0:
        err = giterr_last()
        if err is not NULL and err.klass in ERRORS:
            raise ERRORS[err.klass](err.message)
        else:
            raise LibGit2Error('Unknown error')


cdef class Config:

    cdef git_config* _config

    def __cinit__(Config self):
        self._config = NULL

    def __dealloc__(Config self):
        if self._config is not NULL:
            git_config_free(self._config)

    def get_entry(self, name):
        cdef int error
        cdef const_git_config_entry* entry
        error = git_config_get_entry(
            cython.address(entry), self._config, name)
        check_error(error)
        value = entry.value
        level = entry.level
        return level, value


cdef class Repository:

    cdef git_repository* _repository

    def __cinit__(Repository self):
        self._repository = NULL

    def __dealloc__(Repository self):
        if self._repository is not NULL:
            git_repository_free(self._repository)

    def close(self):
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

    def config(self):
        cdef int error
        assert_repository(self)
        conf = Config()
        error = git_repository_config(cython.address(conf._config),
                                      self._repository)
        check_error(error)
        return conf

    property path:
        def __get__(Repository self):
            return git_repository_path(self._repository)
