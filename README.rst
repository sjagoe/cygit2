======
cygit2
======

``cygit2`` is a wrapper around ``libgit2``, similar fashion to ``pygit2``.
The main difference at the moment is that ``cygit2`` uses cython to wrap
the ``libgit2`` C code rather than using C directly.


Building
========

This assumes that ``libgit2`` has already been built in ``../libgit2`` and
that the ``libgit2`` binaries are in ``../libgit2/bin``

Build with::

  python setup.py build_ext -i -I ../libgit2/include -L../libgit2/bin -lgit2
