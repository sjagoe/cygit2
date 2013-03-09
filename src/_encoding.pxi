# FIXME: I am not sure about default filesystem encoding ...

cdef extern from "Python.h":
    cdef char *Py_FileSystemDefaultEncoding
    cdef char *PyUnicode_GetDefaultEncoding()


cdef bytes _encoding
cdef unicode DEFAULT_ENCODING


if Py_FileSystemDefaultEncoding is not NULL:
    _encoding = Py_FileSystemDefaultEncoding
    DEFAULT_ENCODING = _encoding.decode('ascii')
else:
    _encoding = PyUnicode_GetDefaultEncoding()
    DEFAULT_ENCODING = _encoding.decode('ascii')


# FIXME: Signature
cdef bytes _to_bytes(object string, unicode encoding=None):
    if encoding is None:
        encoding = DEFAULT_ENCODING
    if isinstance(string, bytes):
        return string
    else:
        return string.encode(encoding)
