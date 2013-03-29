======
cygit2
======

.. image:: https://secure.travis-ci.org/sjagoe/cygit2.png
    :alt: Travis CI Build Status
    :target: https://travis-ci.org/sjagoe/cygit2

``cygit2`` is a wrapper around ``libgit2``, similar fashion to ``pygit2``.
The main difference at the moment is that ``cygit2`` uses cython to wrap
the ``libgit2`` C code rather than using C directly.


License
=======

``cygit2`` is licensed under the terms of the GNU GPLv2 with the
libgcc linking exception.  The full terms of the license can be found
in the ``LICENSE`` file included in this distribution.

``cygit2`` includes the ``pygit2`` test suite (in the ``test/``
subdirectory), which is also licensed under the terms of the GNU GPLv2
with the libgcc linking exception.


Building
========

This assumes that ``libgit2`` has already been built in ``../libgit2`` and
that the ``libgit2`` binaries are in ``../libgit2/build``

Build with:

.. code-block:: console

  $ python setup.py build_ext -i -I ../libgit2/include -L../libgit2/build -lgit2

Alternatively you can set the environment variables ``LIBGIT2`` and ``LIBGIT2_LIB``:

.. code-block:: console

    $ LIBGIT2=../libgit2 LIBGIT2_LIB=../libgit2/build python setup.py build_ext -i
