import unittest

from cygit2.tests.fixtures import Cygit2RepositoryFixture


class TestCommit(Cygit2RepositoryFixture):

    def setUp(self):
        super(TestCommit, self).setUp()
        ref = self.repo.lookup_ref('refs/heads/master')
        self.commit = self.repo.lookup_commit(ref.oid)

    def tearDown(self):
        del self.commit
        super(TestCommit, self).tearDown()

    def test_get_committer(self):
        committer = self.commit.committer
        self.assertEqual(committer.name, 'Test User')
        self.assertEqual(committer.email, 'test@users.invalid')

    def test_get_author(self):
        author = self.commit.author
        self.assertEqual(author.name, 'Other User')
        self.assertEqual(author.email, 'other@users.invalid')


if __name__ == '__main__':
    unittest.main()
