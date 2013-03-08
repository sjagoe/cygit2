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


def _format_command(command):
    if sys.platform == 'win32':
        return command.format(sep='&')
    return command.format(sep=';')


def _call_git(command):
    with open(os.devnull, 'w') as devnull:
        check_call(_format_command(command), stdout=devnull, stderr=devnull,
                   shell=True)


def _git_get_commit_ids(path):
    command = '''\
cd {path} {{sep}} \
git log --pretty="%H"
'''.format(path=path)
    stdout = check_output(_format_command(command), shell=True)
    return stdout.decode('ascii').strip().split()


def _git_init(path):
    command = '''\
git init {path} {{sep}} \
cd {path} {{sep}} \
git config user.name "Test User" {{sep}} \
git config user.email "test@users.invalid"
'''.format(path=path)
    _call_git(command)


def _git_add_all(path):
    command = '''\
cd {path} {{sep}} \
git add . \
'''.format(path=path)
    _call_git(command)


def _git_commit(path, message):
    command = '''\
cd {path} {{sep}} \
git commit --author="Other User <other@users.invalid>" -m "{message}" \
'''.format(path=path, message=message)
    _call_git(command)


def _git_remote_add(path, name, target):
    command = '''\
cd {path} {{sep}} \
git remote add "{name}" "target" \
'''.format(path=path, name=name, target=target)
    _call_git(command)


def _git_update_ref(path, ref, sha):
    command = '''\
cd {path} {{sep}} \
git update-ref "{ref}" "{sha}" \
'''.format(path=path, ref=ref, sha=sha)
    _call_git(command)


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
            shutil.rmtree(self.copy_dir)
            raise
        self.repo = Repository.open(repo_dir)

    def tearDown(self):
        self.repo.close()
        shutil.rmtree(self.copy_dir, onerror=onerror)
