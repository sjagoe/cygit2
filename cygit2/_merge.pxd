# This code was automatically generated by CWrap version 0.0.0

cdef extern from "git2.h":

    int git_merge_base(git_oid *out, git_repository *repo, git_oid *one, git_oid *two)

    int git_merge_base_many(git_oid *out, git_repository *repo, git_oid *input_array, size_t length)
