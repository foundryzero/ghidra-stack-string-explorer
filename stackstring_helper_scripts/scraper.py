"""
Scraper
Grabs all constants used as parameters that appear to be strings.
Components within look_ahead of each other are concatenated together
"""

from specific_utilities import find_index_of_similar_scalar
from regional_technique import RegionalTechnique
from stack_string import StackString

try:
    # Typing information for VSCode - Ghidra will not load this section
    # Requires ghidra_stubs from https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    import typing

    if typing.TYPE_CHECKING:
        from ghidra.program.model.listing import Instruction
        from ghidra.program.model.pcode import PcodeOp

# pylint: disable=bare-except
except:
    pass


class Scraper(RegionalTechnique):
    """
    Encapsulates the "Simple Scrape" analysis technique by conditionally scraping
    instructions around a string of interest for constants
    """

    # the string currently being built
    current_string = ""
    # the instruction that started creating the current string
    current_inst = None
    # the index of the operand to current_inst that contains the string
    current_index = None

    def process(self, inst, op):
        # type: (Instruction, PcodeOp) -> None
        """
        Perform technique-specific processing on an instruction and pcode operation
        current_string_part and current_count are up to date when this function is called

        For Scrapper we do no processing on each instruction

        :param inst: The instruction the pcode operation is a part of
        :param op: The pcode operation to parse
        """

    def part_found(self):
        # type () ->  None
        """
        Adds the current parts to the current string
        """
        # if there were string parts found
        current_parts_joined = "".join(self.current_string_parts)

        if self.current_string == "":
            # if no string has been started yet, set the instruction
            # the new string parts come from as the originating instruction
            self.current_inst = self.processing_inst
            self.current_index = find_index_of_similar_scalar(
                current_parts_joined, self.processing_inst
            )

        # add the found string parts from this instruction to the current string
        self.current_string += current_parts_joined

    def end_section(self):
        # type () ->  None
        """
        Terminates the current string and resets
        """
        if len(self.current_string) >= self.min_length:
            self.strings.append(
                StackString(self.current_string, self.current_inst, self.current_index)
            )
        self.current_string = ""

    def reset(self):
        # type () ->  None
        """
        Reset the scraper to initial values
        """
        super(Scraper, self).reset()
        self.current_string = ""
        self.current_inst = None
