# This code was automatically generated by CWrap version 0.0.0

from _types cimport git_repository

from _strarray cimport git_strarray


cdef extern from "git2.h":

    cdef enum git_status_t:
        GIT_STATUS_CURRENT
        GIT_STATUS_INDEX_NEW
        GIT_STATUS_INDEX_MODIFIED
        GIT_STATUS_INDEX_DELETED
        GIT_STATUS_INDEX_RENAMED
        GIT_STATUS_INDEX_TYPECHANGE
        GIT_STATUS_WT_NEW
        GIT_STATUS_WT_MODIFIED
        GIT_STATUS_WT_DELETED
        GIT_STATUS_WT_TYPECHANGE
        GIT_STATUS_IGNORED

    ctypedef int (*git_status_cb)(char *, unsigned int, void *)

    int git_status_foreach(git_repository *repo, git_status_cb callback, void *payload)

    cdef enum __git_status_show_t:
        GIT_STATUS_SHOW_INDEX_AND_WORKDIR
        GIT_STATUS_SHOW_INDEX_ONLY
        GIT_STATUS_SHOW_WORKDIR_ONLY
        GIT_STATUS_SHOW_INDEX_THEN_WORKDIR

    ctypedef __git_status_show_t git_status_show_t

    cdef enum:
        GIT_STATUS_OPTIONS_VERSION

    cdef enum __git_status_opt_t:
        GIT_STATUS_OPT_INCLUDE_UNTRACKED
        GIT_STATUS_OPT_INCLUDE_IGNORED
        GIT_STATUS_OPT_INCLUDE_UNMODIFIED
        GIT_STATUS_OPT_EXCLUDE_SUBMODULES
        GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS
        GIT_STATUS_OPT_DISABLE_PATHSPEC_MATCH

    ctypedef __git_status_opt_t git_status_opt_t

    cdef struct __git_status_options:
        unsigned int version
        git_status_show_t show
        unsigned int flags
        git_strarray pathspec

    ctypedef __git_status_options git_status_options

    int git_status_foreach_ext(git_repository *repo, git_status_options *opts, git_status_cb callback, void *payload)

    int git_status_file(unsigned int *status_flags, git_repository *repo, char *path)

    int git_status_should_ignore(int *ignored, git_repository *repo, char *path)
