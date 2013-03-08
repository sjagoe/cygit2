import os
import shutil
import tempfile
import unittest

from cygit2._cygit2 import Repository, GitStatus, LibGit2RepositoryError, \
    GitObjectType, LibGit2InvalidError

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
        self.assertEqual(os.path.abspath(repo.path),
                         os.path.abspath(os.path.join(self.empty_dir, '.git')))

    def test_repository_init_bare(self):
        self.assertEqual(os.path.abspath(self.empty_repo.path),
                         os.path.abspath(self.repo_dir))
        self.assertTrue(os.path.exists(os.path.join(self.repo_dir, 'config')))

    def test_repository_clone(self):
        source_repo_dir = os.path.abspath(os.path.join(self.empty_dir, 'source'))
        source_repo = Repository.init(source_repo_dir, True)
        self.assertEqual(os.path.abspath(source_repo.path),
                         os.path.abspath(source_repo_dir))
        dest_repo_dir = os.path.join(self.empty_dir, 'dest', '.git')
        if source_repo_dir.startswith('/'):
            uri = 'file://{}'.format(source_repo_dir)
        else:
            uri = 'file:///{}'.format(source_repo_dir)
        dest = Repository.clone(uri, dest_repo_dir)
        self.assertEqual(os.path.abspath(dest.path),
                         os.path.abspath(dest_repo_dir))
        self.assertEqual(
            os.listdir(os.path.dirname(os.path.abspath(dest.path))),
            ['.git'])

    def test_lookup_ref(self):
        # This should raise if there is an error...
        ref = self.empty_repo.lookup_ref('HEAD')

    def test_list_refs(self):
        self.assertEqual(self.empty_repo.list_refs(), ())

    def test_status(self):
        repo = Repository.init(self.empty_dir)
        self.assertEqual(repo.status(), {})
        with open(os.path.join(self.empty_dir, 'file'), 'wb') as fh:
            fh.write(b'contents')
        self.assertEqual(repo.status(),
                         {'file': GitStatus(GitStatus.WT_NEW)})

    def test_status_ext(self):
        repo = Repository.init(self.empty_dir)
        with open(os.path.join(self.empty_dir, 'file'), 'wb') as fh:
            fh.write(b'contents')
        self.assertEqual(repo.status_ext(),
                         {'file': GitStatus(GitStatus.WT_NEW)})
        self.assertEqual(repo.status_ext(include_untracked=False), {})
        self.assertEqual(repo.status_ext(paths=['foo']), {})
        self.assertEqual(repo.status_ext(paths=['file']),
                         {'file': GitStatus(GitStatus.WT_NEW)})


class TestRepositoryWithContents(Cygit2RepositoryFixture):

    def test_list_refs(self):
        self.assertIn('refs/heads/master', self.repo.list_refs())
        self.assertIn('refs/remotes/origin/master', self.repo.list_refs())

    def test_lookup_tree(self):
        ref = self.repo.lookup_ref('refs/heads/master')
        commit = self.repo.lookup_commit(ref.oid)
        # FIXME: insufficient test
        self.repo.lookup_tree(commit.tree_id)

    def test_read_raw_object(self):
        from cygit2._cygit2 import GitOid
        oid = GitOid.from_string(self.commits[0])
        # FIXME: insufficient test
        self.repo.read(oid)

    def test_lookup_commit(self):
        ref = self.repo.lookup_ref('refs/heads/master')
        commit = self.repo.lookup_commit(ref.oid)
        self.assertEqual(commit.oid, ref.oid)

    def test_lookup_object_commit(self):
        ref = self.repo.lookup_ref('refs/heads/master')
        object_ = self.repo.lookup_object(ref.oid, GitObjectType.COMMIT)
        commit = self.repo.lookup_commit(ref.oid)
        self.assertEqual(commit, object_)

    def test_lookup_object_auto_type(self):
        ref = self.repo.lookup_ref('refs/heads/master')
        object_ = self.repo.lookup_object(ref.oid, GitObjectType.ANY)
        commit = self.repo.lookup_commit(ref.oid)
        self.assertEqual(commit, object_)

    def test_lookup_object_tree(self):
        ref = self.repo.lookup_ref('refs/heads/master')
        commit = self.repo.lookup_commit(ref.oid)
        object_ = self.repo.lookup_object(commit.tree_id, GitObjectType.TREE)
        self.assertEqual(commit.tree, object_)

    def test_lookup_object_invalid_type(self):
        ref = self.repo.lookup_ref('refs/heads/master')
        with self.assertRaises(LibGit2InvalidError):
            self.repo.lookup_object(ref.oid, GitObjectType.TREE)


class TestRepositoryClone(Cygit2RepositoryFixture):

    def setUp(self):
        super(TestRepositoryClone, self).setUp()
        self.clone_dir = tempfile.mkdtemp(suffix='-tmp', prefix='cygit2-')

    def tearDown(self):
        shutil.rmtree(self.clone_dir)
        super(TestRepositoryClone, self).tearDown()

    def test_repository_clone(self):
        source_repo_dir = os.path.abspath(self.repo.path)
        dest_repo_dir = os.path.join(self.clone_dir, '.git')
        if source_repo_dir.startswith('/'):
            uri = 'file://{}'.format(source_repo_dir)
        else:
            uri = 'file:///{}'.format(source_repo_dir)
        # dest = Repository.clone(uri, dest_repo_dir)
        # self.assertEqual(os.path.abspath(dest.path),
        #                  os.path.abspath(dest_repo_dir))
        # print os.listdir(os.path.dirname(os.path.abspath(dest.path)))


if __name__ == '__main__':
    unittest.main()
