import os
import shutil
import tempfile
import unittest

from cygit2._cygit2 import Repository


class RepositoryFixture(unittest.TestCase):

    def setUp(self):
        self.repo_dir = tempfile.mkdtemp(suffix='-tmp', prefix='cygit2-')
        self.empty_repo = Repository.init(self.repo_dir, True)

    def tearDown(self):
        self.empty_repo.close()
        shutil.rmtree(self.repo_dir)


class Cygit2RepositoryFixture(unittest.TestCase):

    def setUp(self):
        source_dir = os.path.dirname(os.path.abspath(__file__))
        while not os.path.isdir(os.path.join(source_dir, '.git')):
            source_dir = os.path.dirname(source_dir)
        self._repo_dir = tempfile.mkdtemp(suffix='-tmp', prefix='cygit2-')
        self.repo_path = os.path.join(self._repo_dir, 'cygit2')
        self.repo = Repository.clone(source_dir, self.repo_path)

    def tearDown(self):
        self.repo.close()
        shutil.rmtree(self._repo_dir)
