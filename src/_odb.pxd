# -*- coding: utf-8 -*-
#
# Copyright 2013 The cygit2 contributors
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2,
# as published by the Free Software Foundation.
#
# In addition to the permissions in the GNU General Public License,
# the authors give you unlimited permission to link the compiled
# version of this file into combinations with other programs,
# and to distribute those combinations without any restriction
# coming from the use of this file.  (The General Public License
# restrictions do apply in other respects; for example, they cover
# modification of the file, and distribution when not linked into
# a combined executable.)
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 51 Franklin Street, Fifth Floor,
# Boston, MA 02110-1301, USA.

# This code was automatically generated by CWrap version 0.0.0

from _types cimport \
    git_odb, \
    git_odb_backend, \
    git_odb_object, \
    git_otype

from _oid cimport git_oid

from _odb_backend cimport \
    git_odb_foreach_cb, \
    git_odb_stream, \
    git_odb_writepack

from _indexer cimport \
    git_transfer_progress_callback


cdef extern from "git2.h":

    int git_odb_new(git_odb **out)

    int git_odb_open(git_odb **out, char *objects_dir)

    int git_odb_add_backend(git_odb *odb, git_odb_backend *backend, int priority)

    int git_odb_add_alternate(git_odb *odb, git_odb_backend *backend, int priority)

    int git_odb_add_disk_alternate(git_odb *odb, char *path)

    void git_odb_free(git_odb *db)

    int git_odb_read(git_odb_object **out, git_odb *db, git_oid *id)

    int git_odb_read_prefix(git_odb_object **out, git_odb *db, git_oid *short_id, size_t len)

    int git_odb_read_header(size_t *len_out, git_otype *type_out, git_odb *db, git_oid *id)

    int git_odb_exists(git_odb *db, git_oid *id)

    int git_odb_refresh(git_odb *db)

    int git_odb_foreach(git_odb *db, git_odb_foreach_cb cb, void *payload)

    int git_odb_write(git_oid *out, git_odb *odb, void *data, size_t len, git_otype type)

    int git_odb_open_wstream(git_odb_stream **out, git_odb *db, size_t size, git_otype type)

    int git_odb_open_rstream(git_odb_stream **out, git_odb *db, git_oid *oid)

    int git_odb_write_pack(git_odb_writepack **out, git_odb *db, git_transfer_progress_callback progress_cb, void *progress_payload)

    int git_odb_hash(git_oid *out, void *data, size_t len, git_otype type)

    int git_odb_hashfile(git_oid *out, char *path, git_otype type)

    void git_odb_object_free(git_odb_object *object)

    git_oid *git_odb_object_id(git_odb_object *object)

    void *git_odb_object_data(git_odb_object *object)

    size_t git_odb_object_size(git_odb_object *object)

    git_otype git_odb_object_type(git_odb_object *object)
