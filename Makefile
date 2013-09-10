PY2=../py2-venv/bin/python
PY3=../py3-venv/bin/python

TESTFLAGS=""


default: build2 build3 test2 test3


py2: build2 test2


py3: build3 test3


definitions: \
	src/_attr.pxd \
	src/_blob.pxd \
	src/_branch.pxd \
	src/_checkout.pxd \
	src/_clone.pxd \
	src/_commit.pxd \
	src/_common.pxd \
	src/_config.pxd \
	src/_cred_helpers.pxd \
	src/_diff.pxd \
	src/_errors.pxd \
	src/_graph.pxd \
	src/_ignore.pxd \
	src/_index.pxd \
	src/_indexer.pxd \
	src/_merge.pxd \
	src/_message.pxd \
	src/_net.pxd \
	src/_notes.pxd \
	src/_object.pxd \
	src/_odb.pxd \
	src/_odb_backend.pxd \
	src/_oid.pxd \
	src/_pack.pxd \
	src/_push.pxd \
	src/_refdb.pxd \
	src/_refdb_backend.pxd \
	src/_reflog.pxd \
	src/_refs.pxd \
	src/_refspec.pxd \
	src/_remote.pxd \
	src/_repository.pxd \
	src/_reset.pxd \
	src/_revparse.pxd \
	src/_revwalk.pxd \
	src/_signature.pxd \
	src/_stash.pxd \
	src/_status.pxd \
	src/_strarray.pxd \
	src/_submodule.pxd \
	src/_tag.pxd \
	src/_threads.pxd \
	src/_trace.pxd \
	src/_transport.pxd \
	src/_tree.pxd \
	src/_types.pxd \
	src/_version.pxd

includes: \
	src/_cygit2_types.pxi \
	src/_encoding.pxi \
	src/_enum.pxi \
	src/_error.pxi \
	src/_gitblob.pxi \
	src/_gitcommit.pxi \
	src/_gitconfig.pxi \
	src/_gitindex.pxi \
	src/_gitobject.pxi \
	src/_gitodb.pxi \
	src/_gitoid.pxi \
	src/_gitreference.pxi \
	src/_gitrefspec.pxi \
	src/_gitremote.pxi \
	src/_gitrepository.pxi \
	src/_gitsignature.pxi \
	src/_gitstatus.pxi \
	src/_gittree.pxi

files: definitions includes src/_cygit2.pyx


build2: files
	$(PY2) setup.py build_ext -i -I./libgit2/include -L./libgit2/build

test2:
	LD_LIBRARY_PATH=./libgit2/build $(PY2) -m unittest discover $(TESTFLAGS)

build3: files
	$(PY3) setup.py build_ext -i -I./libgit2/include -L./libgit2/build

test3:
	LD_LIBRARY_PATH=./libgit2/build $(PY3) -m unittest discover $(TESTFLAGS)
