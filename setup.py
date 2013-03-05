from Cython.Distutils.build_ext import build_ext
from setuptools import setup, Extension, find_packages


ext_modules = [
    Extension('cygit2._cygit2',
              ['cygit2/_cygit2.pyx',
               'cygit2/_git2.pxd',
               'cygit2/_types.pxd',
               ],
              ),
    ]


setup(
    name='cygit2',
    version='0.1.0',
    author='Simon Jagoe',
    author_email='simon@simonjagoe.com',
    packages=find_packages(),
    ext_modules=ext_modules,
    cmdclass={'build_ext': build_ext},
)
