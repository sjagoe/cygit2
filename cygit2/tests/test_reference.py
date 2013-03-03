import unittest

from cygit2.tests.fixtures import RepositoryFixture

from cygit2._cygit2 import LibGit2ReferenceError


class TestConfig(RepositoryFixture):

    def test_get_reference(self):
        # Does not raise when getting from repository object
        ref1 = self.empty_repo.lookup_ref('HEAD')

    def test_get_invalid_reference(self):
        with self.assertRaises(LibGit2ReferenceError):
            ref1 = self.empty_repo.lookup_ref('invalid')

    def test_reference_cmp(self):
        # Test that __cmp__ returns 0 for two equal refs.  The two
        # objects here should have different IDs (i.e. are different
        # instances)
        ref1 = self.empty_repo.lookup_ref('HEAD')
        ref2 = self.empty_repo.lookup_ref('HEAD')
        self.assertEqual(ref1, ref2)
        self.assertNotEqual(id(ref1), id(ref2))


if __name__ == '__main__':
    unittest.main()
