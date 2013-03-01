import glob

from cwrap.config import Config, File

GCCXML_INCLUDES = ['./include']


if __name__ == '__main__':
    files = glob.glob('./include/*.h')  + \
            glob.glob('./include/git2/*.h')
    files.remove('./include/git2/stdint.h')
    files.remove('./include/git2/inttypes.h')
    config = Config('gccxml', files=[File(n) for n in files],
                    include_dirs=GCCXML_INCLUDES)
    config.generate()
