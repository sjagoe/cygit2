from cygit2._cygit2 import GitOid, Repository as BaseRepository
from cygit2._cygit2 import LibGit2Error

GIT_OBJ_COMMIT = None
Signature = None
GIT_DIFF_INCLUDE_UNMODIFIED = None
GitError = None
GIT_REF_OID = None
GIT_REF_SYMBOLIC = None
GIT_OBJ_ANY = None
GIT_OBJ_BLOB = None
GIT_OBJ_COMMIT = None
init_repository = None
discover_repository = None
Commit = None
hashfile = None
GIT_SORT_TIME = None
GIT_SORT_REVERSE = None

GIT_STATUS_CURRENT = 0
GIT_STATUS_INDEX_DELETED = 0
GIT_STATUS_INDEX_MODIFIED = 0
GIT_STATUS_INDEX_NEW = 0
GIT_STATUS_WT_DELETED = 0
GIT_STATUS_WT_MODIFIED = 0
GIT_STATUS_WT_NEW = 0


def init_repository(path, bare=False):
    return Repository.init(path, bare=bare)


class Repository(BaseRepository):

    def __getitem__(self, oid_hex):
        oid = GitOid.from_string(oid_hex)
        try:
            return super(Repository, self).__getitem__(oid)
        except LibGit2Error:
            raise KeyError('oid_hex')

    def read(self, oid):
        oid = GitOid.from_string(oid_hex)
        try:
            return super(Repository, self).read(oid)
        except LibGit2Error:
            raise KeyError(oid_hex)
