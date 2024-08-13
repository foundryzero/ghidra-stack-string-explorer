"""
Region Simulator
Simulates instructions after an instruction that contains a string component (is "of interest")
then extracts strings from any memory that is modified
"""

from regional_technique import RegionalTechnique
from simulator import Simulator

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


class RegionSimulator(RegionalTechnique):
    """
    Encapsulates the "Simulate Destinations" analysis technique by simulating
    instructions around a string of interest
    """

    # internal Simulator object that runs the instructions
    simulator = None  # type: Simulator

    def __init__(
        self,
        look_ahead,
        min_length,
        len_of_interest,
        reverse,
        address_filtering_intensity,
    ):
        # type: (int, int, int, bool, str) -> None
        """
        :param look_ahead: The number of instructions to run from the last found string component
        for parts of the same string
        :param first_inst: The first instruction that will be executed by this simulator
        :param min_length: The minimum length of a string to look for
        :param address_filtering_intensity: how strictly strings that may be addresses are filtered
        """
        super(RegionSimulator, self).__init__(
            look_ahead, min_length, len_of_interest, address_filtering_intensity
        )
        self.simulator = Simulator(reverse, min_length, address_filtering_intensity)

    def process(self, inst, op):
        # type: (Instruction, PcodeOp) -> None
        """
        Perform technique-specific processing on an instruction and pcode operation

        :param inst: The instruction the pcode operation is a part of
        :param op: The pcode operation to parse
        """
        self.simulator.run(inst, op)

    def part_found(self):
        # type () ->  None
        """
        Perform technique-specific processing at the end of an instruction if
        new string parts have been found

        For region simulator we do no processing here
        """

    def end_section(self):
        # type () ->  None
        """
        Extracts strings from the current simulator and resets
        """
        new_strings = self.simulator.get_strings()
        self.strings.extend(new_strings)
        self.simulator.reset()

    def reset(self):
        # type () ->  None
        """
        Reset the simulator to initial values
        """
        super(RegionSimulator, self).reset()
        self.simulator.reset()
