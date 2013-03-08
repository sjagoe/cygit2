from subprocess import check_call
import glob
import os

from cwrap.config import Config, File


GCCXML_INCLUDES = ['./include']


if __name__ == '__main__':
    for f in glob.glob('_*.pxd'):
        os.unlink(f)
    files = glob.glob('./include/git2/*.h')
    files.remove('./include/git2/stdint.h')
    files.remove('./include/git2/inttypes.h')
    config = Config('gccxml', files=[File(n) for n in files],
                    include_dirs=GCCXML_INCLUDES)
    config.generate()
    sed = 's/cdef extern from "[_a-z]\+.h"/cdef extern from "git2.h"/'
    for name in glob.glob('_*.pxd'):
        check_call(['sed', '-i', sed, name])
