# This code was automatically generated by CWrap version 0.0.0

from _types cimport \
    git_object, \
    git_otype, \
    git_repository

from _oid cimport git_oid


cdef extern from "git2.h":

    int git_object_lookup(git_object **object, git_repository *repo, git_oid *id, git_otype type)

    int git_object_lookup_prefix(git_object **object_out, git_repository *repo, git_oid *id, size_t len, git_otype type)

    git_oid *git_object_id(git_object *obj)

    git_otype git_object_type(git_object *obj)

    git_repository *git_object_owner(git_object *obj)

    void git_object_free(git_object *object)

    char *git_object_type2string(git_otype type)

    git_otype git_object_string2type(char *str)

    int git_object_typeisloose(git_otype type)

    size_t git_object__size(git_otype type)

    int git_object_peel(git_object **peeled, git_object *object, git_otype target_type)
