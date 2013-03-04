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
        self.copy_dir = tempfile.mkdtemp(suffix='-tmp', prefix='cygit2-')
        repo_dir = os.path.join(self.copy_dir, 'repo')
        shutil.copytree('.', repo_dir)
        self.repo = Repository.open(repo_dir)

    def tearDown(self):
        self.repo.close()
        shutil.rmtree(self.copy_dir)
