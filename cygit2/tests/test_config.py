import unittest

from cygit2.tests.fixtures import RepositoryFixture


class TestConfig(RepositoryFixture):

    def test_get_config(self):
        # Does not raise when getting from repository object
        config = self.empty_repo.config()

    def test_get_config_entry(self):
        config = self.empty_repo.config()
        self.assertEqual(config.get_entry('core.bare')[1], 'true')


if __name__ == '__main__':
    unittest.main()
