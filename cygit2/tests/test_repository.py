import os
import shutil
import tempfile
import unittest

from cygit2._cygit2 import Repository, LibGit2RepositoryError

from cygit2.tests.fixtures import RepositoryFixture, Cygit2RepositoryFixture


class TestEmptyRepository(RepositoryFixture):

    def setUp(self):
        super(TestEmptyRepository, self).setUp()
        self.empty_dir = tempfile.mkdtemp(
            suffix='-tmp', prefix='cygit2-')

    def tearDown(self):
        shutil.rmtree(self.empty_dir)
        super(TestEmptyRepository, self).tearDown()

    def test_repository_open_no_repo(self):
        with self.assertRaises(LibGit2RepositoryError):
            repo = Repository.open(self.empty_dir)

    def test_repository_init(self):
        repo = Repository.init(self.empty_dir)
        self.assertEqual(repo.path, os.path.join(self.empty_dir, '.git/'))

    def test_repository_init_bare(self):
        self.assertEqual(self.empty_repo.path, self.repo_dir + '/')
        self.assertTrue(os.path.exists(os.path.join(self.repo_dir, 'config')))

    def test_repository_clone(self):
        source_repo_dir = os.path.abspath(os.path.join(self.empty_dir, 'source'))
        source_repo = Repository.init(source_repo_dir, True)
        self.assertEqual(source_repo.path, source_repo_dir + '/')
        dest_repo_dir = os.path.join(self.empty_dir, 'dest')
        dest = Repository.clone(source_repo_dir, dest_repo_dir)
        self.assertEqual(dest.path, os.path.join(dest_repo_dir, '.git/'))

    def test_lookup_ref(self):
        # This should raise if there is an error...
        ref = self.empty_repo.lookup_ref('HEAD')

    def test_list_refs(self):
        self.assertEqual(self.empty_repo.list_refs(), ())


class TestRepositoryWithContents(Cygit2RepositoryFixture):

    def test_list_refs(self):
        self.assertIn('refs/heads/master', self.repo.list_refs())
        self.assertIn('refs/remotes/origin/master', self.repo.list_refs())



if __name__ == '__main__':
    unittest.main()
