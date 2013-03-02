import cython

from _git2 cimport git_repository, git_repository_open, git_repository_path, \
    git_repository_init, git_clone


cdef assert_repository(Repository repo):
    if repo._repository is NULL:
        raise RuntimeError('Invalid Repository')



cdef class Repository:

    cdef git_repository* _repository

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
    def clone(cls, path, url):
        repo = Repository()
        git_clone(cython.address(repo._repository), url, path, NULL)
        assert_repository(repo)
        return repo

    property path:
        def __get__(Repository self):
            return git_repository_path(self._repository)
