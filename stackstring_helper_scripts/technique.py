"""
Technique
An abstract class describing a general analysis technique that runs all instructions
and is reset at the end of a section

section - usually a function, but also at the end of a selection

run - called on every pcode operation
end_function - called at the end of a section, should perform finalizing analysis
get_strings - called at the end of a section, should return all strings from that section
reset - called at the end of a section, should reset all member variables back to their default
states but leave configuration settings untouched
"""

from abc import ABCMeta, abstractmethod

try:
    # Typing information for VSCode - Ghidra will not load this section
    # Requires ghidra_stubs from https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    import typing

    if typing.TYPE_CHECKING:
        from typing import List
        from ghidra.program.model.listing import Instruction
        from ghidra.program.model.pcode import PcodeOp
        from stack_string import StackString

# pylint: disable=bare-except
except:
    pass


class Technique:
    """
    Abstract class for analysis strategies
    """

    __metaclass__ = ABCMeta

    @abstractmethod
    def run(self, inst, op):
        # type: (Instruction, PcodeOp) -> None
        """
        Parse a pcode operation

        :param inst: The instruction the pcode operation is a part of
        :param op: The pcode operation to parse
        """

    @abstractmethod
    def end_function(self):
        # type: () -> None
        """
        Performs processing when a function finishes
        """

    @abstractmethod
    def reset(self):
        # type: () -> None
        """
        Reset member variables to original state, but don't reset any settings
        """

    @abstractmethod
    def get_strings(self):
        # type: () -> List[StackString]
        """
        Returns the strings gathered by this technique
        """
