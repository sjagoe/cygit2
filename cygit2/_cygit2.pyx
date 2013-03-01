import cython

from libc.stdint cimport int64_t

from _git2 cimport git_repository, git_repository_open


cdef class Repository:

    cdef git_repository* _repository

    def __init__(Repository self, path):
        git_repository_open(cython.address(self._repository), path)
