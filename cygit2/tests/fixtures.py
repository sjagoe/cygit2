import os
import shutil
import tempfile
import unittest

from cygit2._cygit2 import Repository

def onerror(func, path, exc_info):
    """
    Error handler for ``shutil.rmtree``.

    If the error is due to an access error (read only file)
    it attempts to add write permission and then retries.

    If the error is for another reason it re-raises the error.

    Usage : ``shutil.rmtree(path, onerror=onerror)``

    This has been taken from pathutils.py by Michael Foord 2004 (BSD
    Licensed)

    """
    import stat
    if not os.access(path, os.W_OK):
        # Is the error an access error ?
        os.chmod(path, stat.S_IWUSR)
        func(path)
    else:
        raise


class RepositoryFixture(unittest.TestCase):

    def setUp(self):
        self.repo_dir = tempfile.mkdtemp(suffix='-tmp', prefix='cygit2-')
        self.empty_repo = Repository.init(self.repo_dir, True)

    def tearDown(self):
        self.empty_repo.close()
        shutil.rmtree(self.repo_dir, onerror=onerror)


class Cygit2RepositoryFixture(unittest.TestCase):

    def setUp(self):
        self.copy_dir = tempfile.mkdtemp(suffix='-tmp', prefix='cygit2-')
        repo_dir = os.path.join(self.copy_dir, 'repo')
        shutil.copytree('.', repo_dir)
        self.repo = Repository.open(repo_dir)

    def tearDown(self):
        self.repo.close()
        shutil.rmtree(self.copy_dir, onerror=onerror)
