import os
import shutil
import tempfile
import unittest

from cygit2._cygit2 import Repository, LibGit2ReferenceError

from cygit2.tests.fixtures import RepositoryFixture, Cygit2RepositoryFixture


class TestReferenceEmptyRepository(RepositoryFixture):

    def setUp(self):
        super(TestReferenceEmptyRepository, self).setUp()
        self.ref = self.empty_repo.lookup_ref('HEAD')

    def tearDown(self):
        del self.ref
        super(TestReferenceEmptyRepository, self).tearDown()

    def test_get_invalid_reference(self):
        with self.assertRaises(LibGit2ReferenceError):
            ref = self.empty_repo.lookup_ref('invalid')

    def test_cmp(self):
        # Test that __cmp__ returns 0 for two equal refs.  The two
        # objects here should have different IDs (i.e. are different
        # instances)
        ref2 = self.empty_repo.lookup_ref('HEAD')
        self.assertEqual(self.ref, ref2)
        self.assertNotEqual(id(self.ref), id(ref2))

    def test_name_property(self):
        self.assertEqual(self.ref.name, 'HEAD')

    def test_has_log(self):
        self.assertFalse(self.ref.has_log())

    def test_is_branch_empty_repo(self):
        self.assertFalse(self.ref.is_branch())

    def test_is_packed_empty_repo(self):
        self.assertFalse(self.ref.is_packed())

    def test_is_remote_empty_repo(self):
        self.assertFalse(self.ref.is_remote())

    def test_oid_property_no_ref(self):
        oid = self.ref.oid
        self.assertIsNone(oid)


class TestReference(Cygit2RepositoryFixture):

    def test_oid_property(self):
        ref = self.repo.lookup_ref('refs/heads/master')
        oid = ref.oid

    def test_reload(self):
        ref = self.repo.lookup_ref('refs/heads/master')
        ref.reload()
        self.assertFalse(ref.has_log())

    def test_reflog(self):
        copy_dir = tempfile.mkdtemp(suffix='-tmp', prefix='cygit2-')
        try:
            repo_dir = os.path.join(copy_dir, 'repo')
            shutil.copytree('.', repo_dir)
            repo = Repository.open(repo_dir)
            try:
                ref = repo.lookup_ref('refs/heads/master')
                self.assertGreater(len(list(ref.logs())), 30)
            finally:
                repo.close()
        finally:
            shutil.rmtree(copy_dir)


if __name__ == '__main__':
    unittest.main()
