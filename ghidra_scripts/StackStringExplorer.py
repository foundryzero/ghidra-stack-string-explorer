"""
Finds stack strings and displays according to user preferences
"""

# Finds stack strings and adds to defined strings
# @author
# @category Strings

import os
import sys

# Add . to the system path to allow importing library code
sys.path.insert(
    0,
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "stackstring_helper_scripts",
    ),
)
# pylint: disable=wrong-import-position
from technique import Technique
from simulator import Simulator
from region_simulator import RegionSimulator
from scraper import Scraper
from stack_strings_enums import (
    AnalysisTechnique,
    Domain,
)
from specific_utilities import check_parameters
from parameters import Parameters
from io_utilities import (
    display,
    get_preferences_gui,
    get_preferences_headless,
)

try:
    # Typing information for VSCode - Ghidra will not load this section
    # Requires ghidra_stubs from https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    import typing

    if typing.TYPE_CHECKING:
        from typing import List
        from ghidra.ghidra_builtins import (
            currentProgram,
            currentSelection,
            currentAddress,
            monitor,
            getFunctionContaining,
            getInstructionAt,
            isRunningHeadless,
        )

        # pylint: disable=pointless-statement
        currentProgram, currentSelection, currentAddress, monitor
        getFunctionContaining, getInstructionAt, isRunningHeadless,
# pylint: disable=bare-except
except:
    pass


def stack_strings(params):
    # type: (Parameters) -> None
    """
    Detects stack strings within a program

    :param params: A Parameters object encapsulating the inputs for the program
    """

    # identified strings
    strings = []
    simple_scrape = AnalysisTechnique.SIMPLE_SCRAPE_GUI in params.analysis_techniques
    simulate_regional = (
        AnalysisTechnique.SIMULATE_REGIONAL_GUI in params.analysis_techniques
    )
    simulate_all = AnalysisTechnique.SIMULATE_ALL_GUI in params.analysis_techniques

    # Collect instructions
    instruction_sets = []

    # Current Selection
    if params.domain == Domain.CURRENT_SELECTION:
        if currentSelection is None:
            raise ValueError("No Selection Found")

        instruction_set = []
        address_iterator = currentSelection.getAddresses(True)

        for address in address_iterator:
            inst = getInstructionAt(address)
            if inst is not None and inst not in instruction_set:
                instruction_set.append(inst)

        instruction_sets.append(instruction_set)

    # Current Function
    elif params.domain == Domain.CURRENT_FUNCTION:
        func = getFunctionContaining(currentAddress)
        if func is None:
            raise ValueError("No Function Found")

        func_body = func.getBody()
        listing = currentProgram.getListing()
        inst_iterator = listing.getInstructions(func_body, True)

        instruction_sets.append(inst_iterator)

    # All functions
    elif params.domain == Domain.ALL_FUNCTIONS:
        # get each function
        func_iterator = currentProgram.getFunctionManager().getFunctionsNoStubs(True)
        for func in func_iterator:

            func_body = func.getBody()
            listing = currentProgram.getListing()
            inst_iterator = listing.getInstructions(func_body, True)

            instruction_sets.append(inst_iterator)

    # set up analysis
    techniques = []  # type: List[Technique]

    if simple_scrape:
        scraper = Scraper(
            params.look_ahead,
            params.min_length,
            params.len_of_interest,
            params.address_filtering_intensity,
        )
        techniques.append(scraper)
    if simulate_regional:
        region_simulator = RegionSimulator(
            params.look_ahead,
            params.min_length,
            params.len_of_interest,
            params.reverse,
            params.address_filtering_intensity,
        )
        techniques.append(region_simulator)
    if simulate_all:
        all_simulator = Simulator(
            params.reverse, params.min_length, params.address_filtering_intensity
        )
        techniques.append(all_simulator)

    # set up progress tracking
    monitor.initialize(len(instruction_sets))
    monitor.setMessage("Scanning for strings...")

    # Analyse instructions
    for instruction_set in instruction_sets:

        # get each pcode instruction in this set
        for inst in instruction_set:
            op_iterator = inst.getPcode()
            for op in op_iterator:
                # run analysis
                for technique in techniques:
                    technique.run(inst, op)

        # end analysis and decode strings for this function
        for technique in techniques:
            technique.end_function()
            strings.extend(technique.get_strings())
            technique.reset()

        monitor.incrementProgress()

    # output the strings
    removed_duplicates = []
    for string in strings:
        if string not in removed_duplicates:
            removed_duplicates.append(string)

    display(removed_duplicates, params.output_options)


if __name__ == "__main__":
    if isRunningHeadless():
        parameters = get_preferences_headless()
    else:
        parameters = get_preferences_gui()
    check_parameters(parameters)
    stack_strings(parameters)
