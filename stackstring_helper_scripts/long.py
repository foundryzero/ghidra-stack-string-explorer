"""
This file should never be run. It is used only for the sake of type checking in a
python3 environment while Ghirda runs python2.
"""

try:
    # Typing information for VSCode - Ghidra will not load this section
    # Requires ghidra_stubs from https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    import typing

    if typing.TYPE_CHECKING:
        from typing import Any

# pylint: disable=bare-except
except:
    pass


class long:
    """
    Temp class to shadow Python2 long for type hints
    """

    def __init__(self, num):
        # type: (long, Any) -> None
        pass

    def __add__(self, other):
        # type: (long, long|int) -> long
        return self

    def __sub__(self, other):
        # type: (long, long|int) -> int
        return 0

    def __rsub__(self, other):
        # type: (long, long|int) -> int
        return 0

    def __mul__(self, other):
        # type: (long, long|int) -> long
        return self

    def __rmul__(self, other):
        # type: (long, long|int) -> long
        return self

    def __lt__(self, other):
        # type: (long, long|int) -> bool
        return True

    def __gt__(self, other):
        # type: (long, long|int) -> bool
        return True

    def __rshift__(self, other):
        # type: (long, int) -> long
        return long(0)

    def __and__(self, other):
        # type: (long, int) -> long
        return long(0)
