import os
import sys

from Cython.Distutils.build_ext import build_ext
from setuptools import setup, Command, Extension, find_packages

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



class TestCommand(Command):
    """Command for running unittests without install."""

    user_options = [("args=", None, '''The command args string passed to
                                    unittest framework, such as
                                     --args="-v -f"''')]

    def initialize_options(self):
        self.args = ''
        pass

    def finalize_options(self):
        pass

    def run(self):
        self.run_command('build')
        bld = self.distribution.get_command_obj('build')
        #Add build_lib in to sys.path so that unittest can found DLLs and libs
        sys.path = [os.path.abspath(bld.build_lib)] + sys.path

        import shlex
        import unittest
        test_argv0 = [sys.argv[0] + ' test --args=']
        # For transfering args to unittest, we have to split args by ourself,
        # so that command like:
        #
        #   python setup.py test --args="-v -f"
        #
        # can be executed, and the parameter '-v -f' can be transfering to
        # unittest properly.
        test_argv = test_argv0 + shlex.split(self.args)
        unittest.main(None, defaultTest='test.test_suite', argv=test_argv)


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
    packages=['cygit2', 'pygit2'],
    ext_modules=ext_modules,
    cmdclass={
        'build_ext': build_ext,
        'test': TestCommand,
    },
)
