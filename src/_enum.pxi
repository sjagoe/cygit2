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

cdef class EnumValue:

    cdef object _name
    cdef int _value

    def __init__(self, name, value):
        self._name = name
        self._value = value

    def __repr__(EnumValue self):
        return self.name

    def __richcmp__(EnumValue self not None, EnumValue other not None, int op):
        if op == 2: # ==
            return self.value == other.value
        elif op == 3: # !=
            return self.value != other.value
        elif op == 0: # <
            return self.value < other.value
        elif op == 1: # <= (not >)
            return not (self.value > other.value)
        elif op == 4: # >
            return self.value > other.value
        elif op == 5: # >= (not <)
            return not (self.value < other.value)

    def __hash__(EnumValue self):
        return hash(id(self.name))

    property name:
        def __get__(EnumValue self):
            return self._name

    property value:
        def __get__(EnumValue self):
            return self._value


cdef class ComposableEnumValue(EnumValue):

    def __or__(ComposableEnumValue self, ComposableEnumValue other):
        return CompositeEnumValue(self, other)

    def __ror__(ComposableEnumValue self, ComposableEnumValue other):
        return CompositeEnumValue(other, self)

    cdef CompositeEnumValue _and(ComposableEnumValue self, ComposableEnumValue other):
        _other = set(other.items)
        this = set(self.items)
        return CompositeEnumValue(*sorted(this & _other))

    def __and__(ComposableEnumValue self, ComposableEnumValue other):
        return self._and(other)

    def __rand__(ComposableEnumValue self, ComposableEnumValue other):
        return other._and(self)

    property items:
        def __get__(ComposableEnumValue self):
            return (self,)


cdef class CompositeEnumValue(ComposableEnumValue):

    cdef tuple _items

    def __init__(CompositeEnumValue self, *items):
        flatten = []
        for item in items:
            if not isinstance(item, ComposableEnumValue):
                raise TypeError(
                    ('CompositeEnumValue arguments must all be of '
                     'type \'ComposableEnumValue\': {!r}.').format(item))
            flatten.extend(item.items)
        self._items = tuple(sorted(flatten))

    property name:
        def __get__(CompositeEnumValue self):
            return ' | '.join([v.name for v in self._items])

    property value:
        def __get__(CompositeEnumValue self):
            cdef ComposableEnumValue i
            cdef int value = 0
            for i in self._items:
                value |= i.value
            return value

    property items:
        def __get__(CompositeEnumValue self):
            return self._items
