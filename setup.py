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

import os
from Cython.Distutils.build_ext import build_ext
from setuptools import setup, Extension, find_packages

# Use environment variable LIBGIT2 to set your own libgit2 configuration.
# copied from pygit2 project
libgit2_path = os.getenv("LIBGIT2")
if libgit2_path is None:
    if os.name == 'nt':
        program_files = os.getenv("ProgramFiles")
        libgit2_path = '%s\libgit2' % program_files
    else:
        libgit2_path = '/usr/local'

libgit2_bin = os.path.join(libgit2_path, 'build')
libgit2_include = os.path.join(libgit2_path, 'include')
libgit2_lib = os.getenv('LIBGIT2_LIB', os.path.join(libgit2_path, 'lib'))

ext_modules = [
    Extension(
        'cygit2._cygit2',
        [
            'src/_cygit2.pyx',

            # Includes
            'src/_error.pxi',
            'src/_enum.pxi',
            'src/_encoding.pxi',

            # Definitions
            'src/_attr.pxd',
            'src/_blob.pxd',
            'src/_branch.pxd',
            'src/_checkout.pxd',
            'src/_clone.pxd',
            'src/_commit.pxd',
            'src/_common.pxd',
            'src/_config.pxd',
            'src/_cred_helpers.pxd',
            'src/_diff.pxd',
            'src/_errors.pxd',
            'src/_graph.pxd',
            'src/_ignore.pxd',
            'src/_indexer.pxd',
            'src/_index.pxd',
            'src/_merge.pxd',
            'src/_message.pxd',
            'src/_net.pxd',
            'src/_notes.pxd',
            'src/_object.pxd',
            'src/_odb_backend.pxd',
            'src/_odb.pxd',
            'src/_oid.pxd',
            'src/_pack.pxd',
            'src/_push.pxd',
            'src/_refdb_backend.pxd',
            'src/_refdb.pxd',
            'src/_reflog.pxd',
            'src/_refspec.pxd',
            'src/_refs.pxd',
            'src/_remote.pxd',
            'src/_repository.pxd',
            'src/_reset.pxd',
            'src/_revparse.pxd',
            'src/_revwalk.pxd',
            'src/_signature.pxd',
            'src/_stash.pxd',
            'src/_status.pxd',
            'src/_strarray.pxd',
            'src/_submodule.pxd',
            'src/_tag.pxd',
            'src/_threads.pxd',
            'src/_trace.pxd',
            'src/_transport.pxd',
            'src/_tree.pxd',
            'src/_types.pxd',
            'src/_version.pxd',
        ],
        include_dirs=[libgit2_include],
        library_dirs=[libgit2_lib],
        libraries=['git2'],
    ),
]


setup(
    name='cygit2',
    version='0.1.0',
    author='Simon Jagoe',
    author_email='simon@simonjagoe.com',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Cython',
        'Programming Language :: Python',
        'Topic :: Software Development :: Version Control',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: OS Independent',
        'Operating System :: POSIX',
        'Operating System :: Unix',
    ],
    packages=find_packages(),
    ext_modules=ext_modules,
    cmdclass={'build_ext': build_ext},
)
