from _errors cimport \
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
    GITERR_MERGE, \
    \
    GIT_OK


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


cdef void assert_repository(Repository repo) except *:
    if repo._repository is NULL:
        raise LibGit2Error('Invalid Repository')


cdef void check_error(int error) except *:
    cdef const_git_error *err
    if error != GIT_OK:
        err = giterr_last()
        if err is not NULL and err.klass in ERRORS:
            raise ERRORS[err.klass](err.message)
        else:
            raise LibGit2Error('Unknown error')
