from libc.stdlib cimport malloc
import cython

from _git2 cimport git_repository, git_repository_open, git_repository_path, \
    git_repository_init, git_repository_free
from _git2 cimport git_clone, git_clone_options, GIT_CLONE_OPTIONS_VERSION, \
    GIT_CHECKOUT_OPTS_VERSION, GIT_CHECKOUT_SAFE_CREATE
from _git2 cimport git_remote_callbacks, GIT_REMOTE_CALLBACKS_VERSION
from _git2 cimport const_git_error, giterr_last


cdef assert_repository(Repository repo):
    if repo._repository is NULL:
        raise RuntimeError('Invalid Repository')


cdef git_clone_options make_clone_options():
    cdef git_clone_options opts
    opts.version = GIT_CLONE_OPTIONS_VERSION
    opts.checkout_opts.version = GIT_CHECKOUT_OPTS_VERSION
    opts.checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE_CREATE
    # opts.remote_callbacks = <git_remote_callbacks*>malloc(sizeof(git_remote_callbacks))
    # opts.remote_callbacks.version = GIT_REMOTE_CALLBACKS_VERSION
    # opts.remote_callbacks.progress = NULL
    # opts.remote_callbacks.completion = NULL
    # opts.remote_callbacks.update_tips = NULL
    # opts.remote_callbacks.payload = NULL
    # print <unsigned long>opts.remote_callbacks.progress
    # print <unsigned long>opts.remote_callbacks.completion
    # print <unsigned long>opts.remote_callbacks.update_tips
    # print <unsigned long>opts.remote_callbacks.payload
    return opts


cdef class Repository:

    cdef git_repository* _repository

    def __dealloc__(Repository self):
        if self._repository is not NULL:
            git_repository_free(self._repository)

    @classmethod
    def open(cls, path):
        repo = Repository()
        git_repository_open(cython.address(repo._repository), path)
        assert_repository(repo)
        return repo

    @classmethod
    def init(cls, path, bare=False):
        repo = Repository()
        git_repository_init(cython.address(repo._repository), path, bare)
        assert_repository(repo)
        return repo

    @classmethod
    def clone(cls, url, path):
        cdef int error
        cdef const_git_error* err
        cdef git_clone_options opts = make_clone_options()

        repo = Repository()
        error = git_clone(cython.address(repo._repository), url, path, &opts)
        if error != 0:
            err = giterr_last()
            if err is not NULL:
                raise RuntimeError(err.message)
            else:
                raise RuntimeError('Unknown error')
        assert_repository(repo)
        return repo

    property path:
        def __get__(Repository self):
            return git_repository_path(self._repository)
