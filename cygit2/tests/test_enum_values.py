import unittest

from cygit2._cygit2 import GitStatus

class TestEnumValue(unittest.TestCase):

    def test_composing_enums(self):
        composed1 = GitStatus.INDEX_NEW | GitStatus.INDEX_MODIFIED | GitStatus.WT_NEW
        self.assertGreater(composed1, GitStatus.INDEX_NEW)
        self.assertGreater(composed1, GitStatus.INDEX_MODIFIED)
        self.assertGreater(composed1, GitStatus.WT_NEW)

        composed2 = (GitStatus.INDEX_NEW | GitStatus.WT_NEW) | GitStatus.WT_MODIFIED
        self.assertGreater(composed2, GitStatus.INDEX_NEW)
        self.assertGreater(composed2, GitStatus.WT_NEW)
        self.assertGreater(composed2, GitStatus.WT_MODIFIED)

        composed3 = GitStatus.WT_MODIFIED | (GitStatus.INDEX_NEW | GitStatus.WT_NEW)
        self.assertEqual(composed3, composed2)

        composed4 = (GitStatus.INDEX_NEW | GitStatus.WT_NEW) & GitStatus.WT_MODIFIED
        self.assertEqual(composed4.value, 0)

        composed5 = GitStatus.WT_MODIFIED & (GitStatus.INDEX_NEW | GitStatus.WT_NEW)
        self.assertEqual(composed5, composed4)

        composed6 = (GitStatus.INDEX_NEW | GitStatus.WT_NEW) & GitStatus.WT_NEW
        self.assertEqual(composed6, GitStatus.WT_NEW)

        composed7 = GitStatus.WT_NEW & (GitStatus.INDEX_NEW | GitStatus.WT_NEW)
        self.assertEqual(composed7, GitStatus.WT_NEW)


if __name__ == '__main__':
    unittest.main()
