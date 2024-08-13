"""
Enums
Contains various enums used by the StackStringExplorer program

AnalysisTechnique - The name of different analysis technique options
Domain - The name of various options of what to run on
Configurations - The name and description of general configuration settings
AddressFilteringIntensity - The name and description of different options of how
strictly to filter strings
OutputOption - The name of different ways to output the results

KnownStatus - The name of different categories a value in memory could fall into
"""


class AnalysisTechnique:
    """
    An Enum for Analysis Technique strings used in settings
    Standardizes use to display to user and extract choice

    Simple scrape - uses Scraper class to grab all constants used in a region in the
    order they are used
    Simulate regional - uses Simulator class to simulate a region of code staring
    with an instruction of interest then extract strings from memory
    Simulate all - simulates all the instructions then extracts strings at the end


    Simple scrape is brute force and reliable, but fails if strings are not created
    in order. It can concatenate unrelated strings.

    Simulate regional is the most nuanced technique, but only simulates forward from a
    seen string so may miss some context.

    Simulate all is brute force and unreliable. It often misses strings if they are created
    using the same registers and has too much ambiguity to stitch together the correct string.
    This mode should be used on specific selections when a look-behind is desired and simulate
    regional is insufficient.
    """

    SIMPLE_SCRAPE_GUI = (
        "Simple Scrape (concatenate all printable constants in a region)"
    )
    SIMULATE_REGIONAL_GUI = (
        "Simulate Regions (simulate instructions in a region around a printable string "
        + "and extract strings from modified memory)"
    )
    SIMULATE_ALL_GUI = (
        "Simulate All (simulate all instructions in the range and extract strings "
        + "from modified memory)"
    )

    SIMPLE_SCRAPE_HEADLESS = "Enable Simple Scrape"
    SIMULATE_REGIONAL_HEADLESS = "Enable Simulate Regions"
    SIMULATE_ALL_HEADLESS = "Enable Simulate All"


class Domain:
    """
    An Enum for Domain strings used in settings
    Standardizes use to display to user and extract choice
    """

    CURRENT_SELECTION = "Current Selection"
    CURRENT_FUNCTION = "Current Function"
    ALL_FUNCTIONS = "All Functions"


class Configurations:
    """
    An Enum for Configuration strings used in settings
    Standardizes use to display to user and extract choice
    """

    MIN_LENGTH = "Minimum String Length (discard shorter strings)"
    LOOKAHEAD = "Lookahead (no. instructions between string components)"
    LENGTH_OF_INTEREST = (
        "Minimum length of interest (discard strings moved in smaller blocks)"
    )
    REVERSE = "Reverse the order of string components?"


class AddressFilteringIntensity:
    """
    An Enum for Filtering Intensity strings used in settings
    Standardizes use to display to user and extract choice
    """

    NONE = "Don't filter out any addresses"
    SOME = "Filter out some addresses based on file location"
    ALL = "Aggressively filter addresses based on OperandType"

    NONE_HEADLESS = "none"
    SOME_HEADLESS = "some"
    ALL_HEADLESS = "all"

    NAME = "Address Filtering"


class OutputOption:
    """
    An Enum for Output Option strings used in settings
    Standardizes use to display to user and extract choice
    """

    CONSOLE = "Print to console"
    COMMENT = "Add pre-comment"
    DEFINED = "Add to defined strings (Requires Exclusive Checkout)"


class KnownStatus:
    """
    An Enum for the known status of values

    known -
        string: value is a StackString
        num: value is a long
    unknown - value is an AbstractAddress with multiple components (not BASE)
    or non-zero offset
    unifiable - value is an AbstractAddress with single component (is BASE)
    and zero offset. This means it must be a pure INIT/RESET value
    unified - value is a unifiable that has already been given at least one mapping
    """

    STRING = "string"
    NUM = "num"
    UNKNOWN = "unknown"
    UNIFIABLE = "unifiable"
    UNIFIED = "unified"
