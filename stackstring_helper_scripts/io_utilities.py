"""
IO Utilities
Stores functions used to get input from the user or display the output in Ghidra
"""

from __main__ import (
    currentProgram,
    askChoice,
    askInt,
    askYesNo,
    askChoices,
    askValues,
    createAsciiString,
    getDataAt,
    popup,
)

from ghidra.program.model.symbol import RefType, SourceType
from ghidra.features.base.values import GhidraValuesMap

from stack_strings_enums import (
    AnalysisTechnique,
    Domain,
    Configurations,
    AddressFilteringIntensity,
    OutputOption,
)
from parameters import Parameters

try:
    # Typing information for VSCode - Ghidra will not load this section
    # Requires ghidra_stubs from https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    import typing

    if typing.TYPE_CHECKING:
        from typing import List, Dict
        from ghidra.program.model.address import Address
        from ghidra.program.model.mem import MemoryBlock
        from ghidra.program.model.symbol import ReferenceManager
        from stack_string import StackString

# pylint: disable=bare-except
except:
    pass

# Output


def is_new_string(stack_string, ref_manager):
    # type: (StackString, ReferenceManager) -> bool
    """
    Checks whether the string provided has been found starting at this instruction before

    :param stack_string: The potential new string to check
    :param ref_manager: The reference manager for the program
    :return: False if the string has been found before, True otherwise
    """

    string = stack_string.string
    instruction = stack_string.instruction

    # get all references away from this address
    references = ref_manager.getReferencesFrom(instruction.getAddress())

    # if the data at a reference is this string, then the string has been found before
    for reference in references:
        data = getDataAt(reference.getToAddress())
        if data is not None:
            old_string = data.getValue()
            if old_string == string:
                return False

    # Otherwise, this is a new string
    return True


def display_string(
    stack_string,  # type: StackString
    defined,  # type: bool
    console,  # type: bool
    pre_comment,  # type: bool
    last_address=None,  # type: Address|None
    overlay_block=None,  # type: MemoryBlock|None
    string_locations=None,  # type: Dict[str, Address]|None
):
    # type: (...) -> int
    """
    Displays an individual string in Ghidra

    :param string: The string to be displayed
    :param defined: Whether to show in the defined strings window
    :param console: Whether to print to the console
    :param pre_comment: Whether to add a pre-comment
    :param last_address: The last address written to in the overlay block, defaults to None
    :param overlay_block: The overlay block to write strings to, defaults to None
    :param string_locations: A dictionary of strings to memory locations in the overlay block
    :return: The number of bytes written to overlay_block
    """
    ref_manager = currentProgram.getReferenceManager()
    is_new = is_new_string(stack_string, ref_manager)

    address = stack_string.instruction.getAddress()
    string = stack_string.get_string()
    index = stack_string.get_index()

    bytes_written = 0

    # print to console
    if console and is_new:
        print("Stack string found (" + str(len(string)) + "): " + str(stack_string))

    # add to defined strings
    if defined and is_new:
        if string_locations is None or overlay_block is None or last_address is None:
            print(
                "Something went wrong setting up memory block, skipping defined strings"
            )
            defined = False
        else:
            # convert the string to a byte array
            string_as_bytes = bytearray()
            string_as_bytes.extend(map(ord, string))

            if string not in string_locations:
                # if the string hasn't been written to the overlay block before
                write_address = last_address

                # add to overlay memory block
                overlay_block.putBytes(write_address, string_as_bytes)

                # add to defined strings
                createAsciiString(write_address, len(string_as_bytes))

                string_locations[string] = last_address
                bytes_written = len(string_as_bytes)
            else:
                # if the string had been written to the overlay block before
                write_address = string_locations[string]

            # add reference to defined strings
            # NOTE: This is how we know not to repeat a found string, so be careful if removing
            ref_manager.addMemoryReference(
                address, write_address, RefType.DATA, SourceType.USER_DEFINED, index
            )

    if pre_comment:
        # add comment
        comment = "[str]: " + string
        code_unit = currentProgram.getListing().getCodeUnitAt(address)
        code_unit.setComment(code_unit.PRE_COMMENT, comment)

    return bytes_written


def display(strings, output_options):
    # type: (List[StackString], list[str]) -> None
    """
    Displays the provided strings in Ghidra
    This includes:
    - printing to console
    - adding the strings to a memory overlay block and then to defined strings
    - adding cross references back to the original instruction that formed the string
    - adding a comment at the original instruction

    Warning: Hidden dependency - a string will only print to console if it has not previously
    been added as a defined string

    :param strings: A list of StackString objects to be displayed
    :param output_options: A list of strings describing the output methods to use
    """
    console = OutputOption.CONSOLE in output_options
    pre_comment = OutputOption.COMMENT in output_options
    defined = OutputOption.DEFINED in output_options

    if strings == []:
        return

    string_locations = {}  # type: Dict[str, Address]

    if console:
        print("Stack Strings already in Defined Strings not displayed")

    if defined:
        if currentProgram.hasExclusiveAccess():
            # calculate size of block to be allocated
            lengths = map(lambda x: len(x.string), strings)
            total_length = sum(lengths)

            # set up overlay memory block
            memory = currentProgram.getMemory()
            if total_length < memory.MAX_BLOCK_SIZE:
                overlay_block = memory.createInitializedBlock(
                    "stack strings",
                    currentProgram.getImageBase(),
                    total_length,
                    0,
                    None,
                    True,
                )
                last_address = overlay_block.getStart()
            else:
                popup(
                    "WARNING: Too many strings, larger than maximum block size."
                    + " Strings not added to Defined Strings window"
                )
                defined = False
        else:
            popup(
                "WARNING: No Exclusive Checkout. Strings not added to Defined Strings window"
            )
            defined = False

    for string in strings:
        if defined:
            bytes_written = display_string(
                string,
                defined,
                console,
                pre_comment,
                last_address,
                overlay_block,
                string_locations,
            )
            last_address = last_address.add(bytes_written)

        else:
            display_string(string, defined, console, pre_comment)


# Input


def get_preferences_gui():
    # type () -> Parameters
    """
    Get the configuration for this run from the user

    :return: A Parameters object encapsulating the inputs for the program
    - Minimum length - the minimum length of a string to look for
    - Look ahead - The number of instructions to look ahead from the last found string
    for more string components
    - Analysis techniques - a list of names of the techniques to be performed
    - Length of interest - The number of characters in a single instruction to be of interest
    - Reverse - if True, strings components are compiled from low offset to high, if False string
    components are compiled from high offset to low. Only applies to simulate destinations
    - Output options - a list of names of the ways to output the results
    - Domain - a string of the domain on which to run e.g. current function or all functions
    """

    analysis_choices = [AnalysisTechnique.SIMULATE_REGIONAL_GUI]
    min_length = 3
    look_ahead = 3
    len_of_interest = 2
    reverse = False
    address_filtering = AddressFilteringIntensity.ALL
    output_options = [
        OutputOption.CONSOLE,
        OutputOption.COMMENT,
        OutputOption.DEFINED,
    ]

    # Domain
    domain = askChoice(
        "Domain",
        "Run on:",
        [Domain.CURRENT_SELECTION, Domain.CURRENT_FUNCTION, Domain.ALL_FUNCTIONS],
        Domain.ALL_FUNCTIONS,
    )

    # Use defaults
    yn = askYesNo(
        "Configure",
        "Use Defaults?"
        + "\n*  Analysis techniques: "
        + ", ".join(analysis_choices)
        + "\n*  Minimum length: "
        + str(min_length)
        + "\n*  Look ahead: "
        + str(look_ahead)
        + "\n*  Length of interest: "
        + str(len_of_interest)
        + "\n*  Address Filtering: "
        + str(address_filtering)
        + "\n*  Output options: "
        + ", ".join(output_options),
    )
    if not yn:
        # Analysis techniques
        analysis_choices = askChoices(
            "Analysis",
            "Choose which analysis techniques to run",
            [
                AnalysisTechnique.SIMPLE_SCRAPE_GUI,
                AnalysisTechnique.SIMULATE_REGIONAL_GUI,
                AnalysisTechnique.SIMULATE_ALL_GUI,
            ],
        )

        # # General Config
        value_map = GhidraValuesMap()

        # min_length
        value_map.defineInt(Configurations.MIN_LENGTH, min_length)

        if (
            AnalysisTechnique.SIMPLE_SCRAPE_GUI in analysis_choices
            or AnalysisTechnique.SIMULATE_REGIONAL_GUI in analysis_choices
        ):
            # look_ahead
            value_map.defineInt(Configurations.LOOKAHEAD, look_ahead)

            # len_of_interest
            value_map.defineInt(Configurations.LENGTH_OF_INTEREST, len_of_interest)

        if (
            AnalysisTechnique.SIMULATE_REGIONAL_GUI in analysis_choices
            or AnalysisTechnique.SIMULATE_ALL_GUI in analysis_choices
        ):
            # reverse
            value_map.defineBoolean(Configurations.REVERSE, reverse)

        # address_filtering
        value_map.defineChoice(
            AddressFilteringIntensity.NAME,
            address_filtering,
            [
                AddressFilteringIntensity.NONE,
                AddressFilteringIntensity.SOME,
                AddressFilteringIntensity.ALL,
            ],
        )

        responses = askValues("Configure", "General Settings", value_map)

        # Extract results from General Config
        # min_length
        min_length = responses.getInt(Configurations.MIN_LENGTH)

        if (
            AnalysisTechnique.SIMPLE_SCRAPE_GUI in analysis_choices
            or AnalysisTechnique.SIMULATE_REGIONAL_GUI in analysis_choices
        ):
            # look_ahead
            look_ahead = responses.getInt(Configurations.LOOKAHEAD)
            # len_of_interest
            len_of_interest = responses.getInt(Configurations.LENGTH_OF_INTEREST)

        if (
            AnalysisTechnique.SIMULATE_REGIONAL_GUI in analysis_choices
            or AnalysisTechnique.SIMULATE_ALL_GUI in analysis_choices
        ):
            # reverse
            reverse = responses.getBoolean(Configurations.REVERSE)

        # address_filtering
        address_filtering = responses.getChoice(AddressFilteringIntensity.NAME)

        # Output choices
        output_options = askChoices(
            "Output",
            "Choose how to display results",
            [
                OutputOption.CONSOLE,
                OutputOption.COMMENT,
                OutputOption.DEFINED,
            ],
        )

    return Parameters(
        min_length,
        look_ahead,
        analysis_choices,
        len_of_interest,
        reverse,
        output_options,
        domain,
        address_filtering,
    )


def get_preferences_headless():
    # type: () -> Parameters
    """
    Get the configuration for this run from the user
    This may error if the inputs in StackStrings.properties are incorrect

    :return: A Parameters object encapsulating the inputs for the program
    - Minimum length - the minimum length of a string to look for
    - Look ahead - The number of instructions to look ahead from the last found string
    for more string components
    - Analysis techniques - a list of names of the techniques to be performed
    - Length of interest - The number of characters in a single instruction to be of interest
    - Reverse - if True, strings components are compiled from low offset to high, if False string
    components are compiled from high offset to low. Only applies to simulate destinations
    - Output options - a list of names of the ways to output the results
    - Domain - a string of the domain on which to run e.g. current function or all functions
    """

    # Domain - other domains are not available in headless mode
    domain = Domain.ALL_FUNCTIONS

    # Analysis techniques
    analysis_choices = []
    if askYesNo("Analysis", AnalysisTechnique.SIMPLE_SCRAPE_HEADLESS):
        analysis_choices.append(AnalysisTechnique.SIMPLE_SCRAPE_GUI)
    if askYesNo("Analysis", AnalysisTechnique.SIMULATE_REGIONAL_HEADLESS):
        analysis_choices.append(AnalysisTechnique.SIMULATE_REGIONAL_GUI)
    if askYesNo("Analysis", AnalysisTechnique.SIMULATE_ALL_HEADLESS):
        analysis_choices.append(AnalysisTechnique.SIMULATE_ALL_GUI)

    # # General Config
    min_length = askInt("Config", Configurations.MIN_LENGTH)

    look_ahead = askInt("Config", Configurations.LOOKAHEAD)

    len_of_interest = askInt("Config", Configurations.LENGTH_OF_INTEREST)

    reverse = askYesNo("Config", Configurations.REVERSE)

    address_filtering = askChoice(
        "Config",
        AddressFilteringIntensity.NAME,
        [
            AddressFilteringIntensity.NONE_HEADLESS,
            AddressFilteringIntensity.SOME_HEADLESS,
            AddressFilteringIntensity.ALL_HEADLESS,
        ],
        AddressFilteringIntensity.SOME_HEADLESS,
    )

    if address_filtering == AddressFilteringIntensity.NONE_HEADLESS:
        address_filtering = AddressFilteringIntensity.NONE
    if address_filtering == AddressFilteringIntensity.SOME_HEADLESS:
        address_filtering = AddressFilteringIntensity.SOME
    if address_filtering == AddressFilteringIntensity.ALL_HEADLESS:
        address_filtering = AddressFilteringIntensity.ALL

    # Output choices
    output_options = []
    if askYesNo("Output", OutputOption.CONSOLE):
        output_options.append(OutputOption.CONSOLE)
    if askYesNo("Output", OutputOption.COMMENT):
        output_options.append(OutputOption.COMMENT)
    if askYesNo("Output", OutputOption.DEFINED):
        output_options.append(OutputOption.DEFINED)

    return Parameters(
        min_length,
        look_ahead,
        analysis_choices,
        len_of_interest,
        reverse,
        output_options,
        domain,
        address_filtering,
    )
