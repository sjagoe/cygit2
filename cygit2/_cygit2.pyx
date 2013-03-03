import cython

from _git2 cimport git_repository, git_repository_open, git_repository_path, \
    git_repository_init, git_repository_free
from _git2 cimport git_clone
from _git2 cimport const_git_error, giterr_last


class LibGit2Error(Exception): pass


cdef assert_repository(Repository repo):
    if repo._repository is NULL:
        raise LibGit2Error('Invalid Repository')


cdef check_error(int error):
    cdef const_git_error* err
    if error != 0:
        err = giterr_last()
        if err is not NULL:
            raise LibGit2Error(err.message)
        else:
            raise LibGit2Error('Unknown error')


cdef class Repository:

    cdef git_repository* _repository

    def __dealloc__(Repository self):
        if self._repository is not NULL:
            git_repository_free(self._repository)

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

    property path:
        def __get__(Repository self):
            return git_repository_path(self._repository)
