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
            'cygit2/_cygit2.pyx',

            # Includes
            'cygit2/_error.pxi',
            'cygit2/_enum.pxi',
            'cygit2/_encoding.pxi',

            # Definitions
            'cygit2/_attr.pxd',
            'cygit2/_blob.pxd',
            'cygit2/_branch.pxd',
            'cygit2/_checkout.pxd',
            'cygit2/_clone.pxd',
            'cygit2/_commit.pxd',
            'cygit2/_common.pxd',
            'cygit2/_config.pxd',
            'cygit2/_cred_helpers.pxd',
            'cygit2/_diff.pxd',
            'cygit2/_errors.pxd',
            'cygit2/_graph.pxd',
            'cygit2/_ignore.pxd',
            'cygit2/_indexer.pxd',
            'cygit2/_index.pxd',
            'cygit2/_merge.pxd',
            'cygit2/_message.pxd',
            'cygit2/_net.pxd',
            'cygit2/_notes.pxd',
            'cygit2/_object.pxd',
            'cygit2/_odb_backend.pxd',
            'cygit2/_odb.pxd',
            'cygit2/_oid.pxd',
            'cygit2/_pack.pxd',
            'cygit2/_push.pxd',
            'cygit2/_refdb_backend.pxd',
            'cygit2/_refdb.pxd',
            'cygit2/_reflog.pxd',
            'cygit2/_refspec.pxd',
            'cygit2/_refs.pxd',
            'cygit2/_remote.pxd',
            'cygit2/_repository.pxd',
            'cygit2/_reset.pxd',
            'cygit2/_revparse.pxd',
            'cygit2/_revwalk.pxd',
            'cygit2/_signature.pxd',
            'cygit2/_stash.pxd',
            'cygit2/_status.pxd',
            'cygit2/_strarray.pxd',
            'cygit2/_submodule.pxd',
            'cygit2/_tag.pxd',
            'cygit2/_threads.pxd',
            'cygit2/_trace.pxd',
            'cygit2/_transport.pxd',
            'cygit2/_tree.pxd',
            'cygit2/_types.pxd',
            'cygit2/_version.pxd',
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
        'License :: OSI Approved :: BSD License',
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
