import unittest

from cygit2._cygit2 import LibGit2ReferenceError

from cygit2.tests.fixtures import RepositoryFixture


class TestReference(RepositoryFixture):

    def setUp(self):
        super(TestReference, self).setUp()
        self.ref = self.empty_repo.lookup_ref('HEAD')

    def tearDown(self):
        del self.ref
        super(TestReference, self).tearDown()

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


if __name__ == '__main__':
    unittest.main()
