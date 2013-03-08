# This code was automatically generated by CWrap version 0.0.0

cdef extern from "git2.h":

    int git_packbuilder_new(git_packbuilder **out, git_repository *repo)

    unsigned int git_packbuilder_set_threads(git_packbuilder *pb, unsigned int n)

    int git_packbuilder_insert(git_packbuilder *pb, git_oid *id, char *name)

    int git_packbuilder_insert_tree(git_packbuilder *pb, git_oid *id)

    int git_packbuilder_write(git_packbuilder *pb, char *file)

    ctypedef int (*git_packbuilder_foreach_cb)(void *, size_t, void *)

    int git_packbuilder_foreach(git_packbuilder *pb, git_packbuilder_foreach_cb cb, void *payload)

    uint32_t git_packbuilder_object_count(git_packbuilder *pb)

    uint32_t git_packbuilder_written(git_packbuilder *pb)

    void git_packbuilder_free(git_packbuilder *pb)
