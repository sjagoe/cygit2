# This code was automatically generated by CWrap version 0.0.0

cdef extern from "strarray.h":

    cdef struct git_strarray:
        char **strings
        size_t count

    ctypedef git_strarray git_strarray

    void git_strarray_free(git_strarray *array)

    int git_strarray_copy(git_strarray *tgt, git_strarray *src)


