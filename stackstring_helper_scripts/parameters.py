"""
Parameters
Stores the parameters for the program
"""

try:
    # Typing information for VSCode - Ghidra will not load this section
    # Requires ghidra_stubs from https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    import typing

    if typing.TYPE_CHECKING:
        from typing import List

# pylint: disable=bare-except
except:
    pass


class Parameters:
    """
    Stores the parameters for the program
    """

    def __init__(
        self,
        min_length,
        look_ahead,
        analysis_techniques,
        len_of_interest,
        reverse,
        output_options,
        domain,
        address_filtering_intensity,
    ):
        # type: (int, int, List[str], int, bool, List[str], str, str) -> None
        """
        :param min_length: The minimum length of a string to look for
        :param look_ahead: The number of instructions to look ahead from the last found string
        for more string components
        :param analysis_techniques: a list of names of the techniques to be performed
        :param len_of_interest: The number of characters in a single instruction to be of interest
        :param reverse: if True, strings components are compiled from low offset to high, if False
        string components are compiled from high offset to low.
        :param output_options: a list of names of the ways to output the results
        :param domain: a string of the domain on which to run e.g. current function or all functions
        :param address_filtering_intensity: The degree to which strings that look like addresses
        should be removed
        """
        self.min_length = min_length
        self.look_ahead = look_ahead
        self.analysis_techniques = analysis_techniques
        self.len_of_interest = len_of_interest
        self.output_options = output_options
        self.domain = domain
        self.reverse = reverse
        self.address_filtering_intensity = address_filtering_intensity
