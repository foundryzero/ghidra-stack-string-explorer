"""
StackString
Captures information about a string component found in memory that is useful to keep
together.
This includes
- The string value
- The instruction containing the start of the string value
- The index of the operand in that instruction that contains the string value
"""

from general_utilities import convert_string_to_num

try:
    # Typing information for VSCode - Ghidra will not load this section
    # Requires ghidra_stubs from https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    import typing

    if typing.TYPE_CHECKING:
        from ghidra.program.model.listing import Instruction

# pylint: disable=bare-except
except:
    pass


class StackString:
    """
    Associates a string with the instruction that first starts creating it to help
    find the string in the binary when the string is reported.

    :param string: A stack string string found in the program
    :param instruction: The instruction that starts creating the string
    :param index: The index of the operand to instruction that contains the string
    """

    instruction = None  # type: Instruction
    string = ""
    index = None  # type: int

    def __init__(self, string, instruction, index):
        # type: (str, Instruction, int) -> None
        self.instruction = instruction
        self.string = string
        self.index = index

    def get_string(self):
        # type: () -> str
        """
        Getter for the captured string

        :return: The captured string
        """
        return self.string

    def get_instruction(self):
        # type: () -> Instruction
        """
        Getter for the captured instruction

        :return: The captured instruction
        """
        return self.instruction

    def get_index(self):
        # type: () -> int
        """
        Getter for the captured index

        :return: The captured index
        """
        return self.index

    def __str__(self):
        representation = self.string
        representation = representation.replace("\n", "\\n")
        representation = representation.replace("\t", "\\t")
        representation = representation.replace("\r", "\\r")
        representation = representation.replace("\x0b", "\\x0b")
        representation = representation.replace("\x0c", "\\x0c")
        return representation + " @ 0x" + str(self.instruction.getAddress())

    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        return (
            isinstance(other, StackString)
            and self.string == other.get_string()
            and self.instruction.getAddress() == other.get_instruction().getAddress()
        )

    def __len__(self):
        return len(self.string)

    def __hash__(self):
        return convert_string_to_num(str(self))
