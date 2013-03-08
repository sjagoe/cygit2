# This code was automatically generated by CWrap version 0.0.0

from _checkout cimport git_checkout_opts

from _indexer cimport git_transfer_progress_callback

from _transport cimport \
    git_cred_acquire_cb, \
    git_transport

from _types cimport \
    git_remote_callbacks, \
    git_repository

from _remote cimport git_remote_autotag_option_t


cdef extern from "git2.h":

    cdef struct git_clone_options:
        unsigned int version
        git_checkout_opts checkout_opts
        int bare
        git_transfer_progress_callback fetch_progress_cb
        void *fetch_progress_payload
        char *remote_name
        char *pushurl
        char *fetch_spec
        char *push_spec
        git_cred_acquire_cb cred_acquire_cb
        void *cred_acquire_payload
        git_transport *transport
        git_remote_callbacks *remote_callbacks
        git_remote_autotag_option_t remote_autotag
        char *checkout_branch

    ctypedef git_clone_options git_clone_options

    int git_clone(git_repository **out, char *url, char *local_path, git_clone_options *options)
