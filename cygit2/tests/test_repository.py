import os
import shutil
import tempfile
import unittest

from cygit2._cygit2 import Repository


class TestRepository(unittest.TestCase):

    def setUp(self):
        self.repo_dir = tempfile.mkdtemp(suffix='-tmp', prefix='cygit2-')
        # self.repo_dir = '/home/simon/workspace/source/pygit2'

    def tearDown(self):
        shutil.rmtree(self.repo_dir)

    def test_repository_open_no_repo(self):
        with self.assertRaises(RuntimeError):
            repo = Repository.open(self.repo_dir)


if __name__ == '__main__':
    unittest.main()
