# This code was automatically generated by CWrap version 0.0.0

cdef extern from "git2.h":

    int git_revparse_single(git_object **out, git_repository *repo, char *spec)
