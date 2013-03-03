import cython

from _git2 cimport \
    git_repository, git_repository_open, git_repository_path, \
    git_repository_init, git_repository_free, git_repository_config, \
    git_config, git_config_free, \
    const_git_config_entry, git_config_get_entry, \
    git_clone, \
    const_git_error, giterr_last


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


cdef class Config:

    cdef git_config* _config

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
