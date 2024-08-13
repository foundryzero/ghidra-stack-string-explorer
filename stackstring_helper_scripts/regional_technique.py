"""
Regional Technique
An abstract class describing an analysis technique that runs instructions after an
instruction that contains a string component (is "of interest")

process - called on every pcode operation
part_found - called after every instruction of interest
end_section - called after the last instruction after an instruction of interest that is
considered to be close enough to it to contain more components of the same string
"""

from abc import abstractmethod
from specific_utilities import get_strings
from technique import Technique

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


class RegionalTechnique(Technique):
    """
    Abstract class for analysis techniques that evaluate over some region around detected
    strings

    Does nothing until a string is found using get_strings on opcodes in an instruction
    Performs active processing on all instructions starting from this one until look_ahead
    instructions have passed without a detected string
    Then compiles strings and adds them to strings member

    current_count - starts above look_ahead. Increments when an instruction ends and had
    no strings from get_strings. Resets to 0 when an instruction ends and had strings
    from get_strings.
    When current_count <= look_ahead we are considered to be actively processing
    When current_count == look_ahead we are skipping instructions

    current_string_parts - the string parts accumulated from the pcode operations in the
    current instruction so far e.g. will contain all string parts from one instruction when
    part_found() or end_section() are called at the end of an instruction.

    processing_inst - the instruction currently being processed

    Call process() on all pcode operations issued to the technique
    At the end of an instruction,
        Call part_found() where strings have been found in the instruction
        Call end_section() if current_count >= look_ahead

    This results in sections of one instruction for any instructions not in an active region
    and sections containing all of the instructions in each of the active regions
    """

    # strings found
    strings = []  # type: List[StackString]
    # number of instructions to look ahead of a string component for further components
    look_ahead = 0
    # minimum length of string to report
    min_length = 0
    # how strictly to filter out strings that may be addresses
    address_filtering_intensity = None  # type: str
    # minimum length of string in a single instruction to be interesting
    len_of_interest = 0
    # the current number of instructions since the last string section
    current_count = 0
    # the string parts from the current instruction
    current_string_parts = []  # type: List[str]
    # the current instruction being processed
    processing_inst = None

    def __init__(
        self, look_ahead, min_length, len_of_interest, address_filtering_intensity
    ):
        # type: (int, int, int, str) -> None
        """
        :param look_ahead: The number of instructions to scrape from the last found string component
        for parts of the same string
        :param min_length: The minimum length of a string to look for
        :param len_of_interest: The minimum length of string in a single instruction to be of
        :param address_filtering_intensity: how strictly strings that may be addresses are filtered
        """
        self.look_ahead = look_ahead
        self.min_length = min_length
        self.address_filtering_intensity = address_filtering_intensity
        self.len_of_interest = len_of_interest
        self.current_count = look_ahead + 10

    @abstractmethod
    def process(self, inst, op):
        # type: (Instruction, PcodeOp) -> None
        """
        Perform technique-specific processing on an instruction and pcode operation

        :param inst: The instruction the pcode operation is a part of
        :param op: The pcode operation to parse
        """

    @abstractmethod
    def part_found(self):
        # type () ->  None
        """
        Perform technique-specific processing at the end of an instruction if
        new string parts have been found
        """

    @abstractmethod
    def end_section(self):
        # type () ->  None
        """
        Perform technique-specific processing when a processing section is finished
        See above for definition of a processing section
        """

    def end_instruction(self):
        # type: () -> None
        """
        Update the count and perform processing after the last opcode for an instruction
        is issued
        """
        # pass if there is no instruction to be terminated
        if self.processing_inst is None:
            return

        if len(self.current_string_parts) == 0:
            # if there were no string parts found, increment the count
            self.current_count += 1
        else:
            self.part_found()
            # if string parts were found, reset the count
            self.current_count = 0

        # reset the string parts for the next instruction
        self.current_string_parts = []

        if self.current_count >= self.look_ahead:
            # if too many instructions have passed without a string part
            self.end_section()

    def run(self, inst, op):
        # type: (Instruction, PcodeOp) -> None
        """
        Parse a pcode operation

        :param inst: The instruction the pcode operation is a part of
        :param op: The pcode operation to parse
        """
        if inst != self.processing_inst:
            # if the previous instruction is finished
            self.end_instruction()

            # switch to executing the new instruction
            self.processing_inst = inst

        # add the string parts from this pcode op to those for the instruction overall
        self.current_string_parts.extend(
            get_strings(
                op,
                inst,
                self.current_count,
                self.current_string_parts,
                self.len_of_interest,
                self.address_filtering_intensity,
            )
        )

        self.process(inst, op)

    def end_function(self):
        # type () ->  None
        """
        Performs processing when a function finishes
        """
        self.end_instruction()
        self.end_section()

    def reset(self):
        # type () ->  None
        """
        Reset member variables
        """
        self.strings = []
        self.current_count = 0
        self.current_string_parts = []
        self.processing_inst = None

    def get_strings(self):
        # type () ->  List[StackString]
        """
        Return strings gathered by this technique

        :return: A list of StackStrings
        """
        return self.strings
