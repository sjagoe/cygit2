import cython

from libc.stdlib cimport malloc

from _git2 cimport git_repository, git_repository_open, git_repository_path, \
    git_clone, git_clone_options


cdef class Repository:

    cdef git_repository* _repository

    @classmethod
    def open(cls, path):
        repo = Repository()
        git_repository_open(cython.address(repo._repository), path)
        if repo._repository is NULL:
            raise RuntimeError('No repository at {!r}'.format(path))
        return repo

    property path:
        def __get__(Repository self):
            return git_repository_path(self._repository)
