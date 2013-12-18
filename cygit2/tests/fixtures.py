# -*- coding: utf-8 -*-
#
# Copyright 2013 The cygit2 contributors
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2,
# as published by the Free Software Foundation.
#
# In addition to the permissions in the GNU General Public License,
# the authors give you unlimited permission to link the compiled
# version of this file into combinations with other programs,
# and to distribute those combinations without any restriction
# coming from the use of this file.  (The General Public License
# restrictions do apply in other respects; for example, they cover
# modification of the file, and distribution when not linked into
# a combined executable.)
#
# This file is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 51 Franklin Street, Fifth Floor,
# Boston, MA 02110-1301, USA.

from subprocess import check_call, check_output
import os
import shutil
import sys
import tempfile
import unittest

from cygit2._cygit2 import Repository

def onerror(func, path, exc_info):
    """
    Error handler for ``shutil.rmtree``.

    If the error is due to an access error (read only file)
    it attempts to add write permission and then retries.

    If the error is for another reason it re-raises the error.

    Usage : ``shutil.rmtree(path, onerror=onerror)``

    This has been taken from pathutils.py by Michael Foord 2004 (BSD
    Licensed)

    """
    import stat
    if not os.access(path, os.W_OK):
        # Is the error an access error ?
        os.chmod(path, stat.S_IWUSR)
        func(path)
    else:
        raise


class RepositoryFixture(unittest.TestCase):

    def setUp(self):
        self.repo_dir = tempfile.mkdtemp(suffix='-tmp', prefix='cygit2-')
        self.empty_repo = Repository.init(self.repo_dir, True)

    def tearDown(self):
        self.empty_repo.close()
        shutil.rmtree(self.repo_dir, onerror=onerror)


def _call_git(command, cwd):
    with open(os.devnull, 'w') as devnull:
        check_call(command, stdout=devnull, stderr=devnull, cwd=cwd)


def _git_get_commit_ids(path):
    stdout = check_output(['git', 'log', '--pretty="%H"'], cwd=path)
    return stdout.decode('ascii').strip().replace('"', '').split()


def _git_init(path):
    _call_git(['git', 'init', path], cwd=os.path.dirname(path))
    _call_git(['git', 'config', 'user.name', 'Test User'], cwd=path)
    _call_git(['git', 'config', 'user.email', 'test@users.invalid'], cwd=path)


def _git_add_all(path):
    _call_git(['git', 'add', '.'], cwd=path)


def _git_commit(path, message):
    _call_git(
        [
            'git',
            'commit',
            '--author="Other User <other@users.invalid>"',
            '-m',
            message,
        ],
        cwd=path,
    )


def _git_remote_add(path, name, target):
    _call_git(['git', 'remote', 'add', name, target], cwd=path)


def _git_update_ref(path, ref, sha):
    _call_git(['git', 'update-ref', ref, sha], cwd=path)


class Cygit2RepositoryFixture(unittest.TestCase):

    def setUp(self):
        self.copy_dir = tempfile.mkdtemp(suffix='-tmp', prefix='cygit2-')
        repo_dir = os.path.join(self.copy_dir, 'repo')
        source_path = os.path.join(os.path.dirname(__file__), 'data')
        shutil.copytree(source_path, repo_dir)
        try:
            _git_init(repo_dir)
            _git_add_all(repo_dir)
            _git_commit(repo_dir, 'First commit')
            _git_remote_add(repo_dir, 'origin', 'git://example.invalid/.git')
            self.commits = _git_get_commit_ids(repo_dir)
            _git_update_ref(repo_dir, 'refs/remotes/origin/master', self.commits[0])
        except Exception:
            # shutil.rmtree(self.copy_dir, onerror=onerror)
            raise
        self.repo = Repository.open(repo_dir)

    def tearDown(self):
        self.repo.close()
        shutil.rmtree(self.copy_dir, onerror=onerror)
