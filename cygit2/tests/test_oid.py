#import faulthandler
#faulthandler.enable()

import unittest

from cygit2._cygit2 import GitOid


class TestGitOid(unittest.TestCase):

    def test_oid_short(self):
        oid = GitOid.from_string('abc123efab')
        self.assertEqual(oid.hex, 'abc123efab')

    def test_oid_full(self):
        oid = GitOid.from_string('abc123efababc123efababc123efababc123efab')
        self.assertEqual(oid.hex, 'abc123efababc123efababc123efababc123efab')


if __name__ == '__main__':
    unittest.main()
