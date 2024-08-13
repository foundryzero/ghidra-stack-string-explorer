"""
General Utilities
Stores functions applicable outside of the classes and types used in the StackStringExplorer program
"""

from string import printable

try:
    # Typing information for VSCode - Ghidra will not load this section
    # Requires ghidra_stubs from https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    import typing

    if typing.TYPE_CHECKING:
        from typing import List
        from long import long

# pylint: disable=bare-except
except:
    pass


def convert_num_to_string(number):
    # type: (long | None) -> str|None
    """
    Returns the characters decoded from the number provided, or None if the characters
    are not printable

    :param data: The number to be converted
    :return: The character string, or None
    """
    if number:
        # catches both data is None and 0
        chars = ""
        while number:
            # get the least significant character
            char = chr(number & 0xFF)
            # check that it is in a printable range
            if char in printable:
                chars += char
            else:
                # fail if the scalar contains non-printable characters
                return None
            number = (number >> 8) & 0x00FFFFFFFFFFFFFF
        return chars
    return None


def convert_string_to_num(string):
    # type: (str) -> int
    """
    Converts a string constant into the integer that could be interpreted from the same bytes

    :param data: the string to be converted
    :return: an integer representation of the same bytes
    """
    number = 0
    for i, char in enumerate(string):
        num = ord(char) << (i * 8)
        number += num

    return number


def replace_section(string, to_insert, start_index):
    # type: (str, str, int) -> str
    """
    Replaces the characters from offset start_index into the string with the string to_insert

    :param string: String to have section replaced
    :param to_insert: String to replace section of string
    :param start_index: Index of string to start the replacement at
    :return: The new string
    """
    return string[:start_index] + to_insert + string[start_index + len(to_insert) :]


def reorder(string, component_start_indexes):
    # type: (str, List[int]) -> str
    """
    Reverse the order of components in a string where each component is delimitated by
    indexes in a given list

    :param string: The string containing components
    :param component_start_indexes: The indexes of the start of each component
    :return: The reordered string
    """
    if len(component_start_indexes) < 2:
        return string
    component_start_indexes.sort(reverse=True)
    new_string = string[component_start_indexes[0] :]
    for i, start_index in enumerate(component_start_indexes[1:]):
        end_index = component_start_indexes[i]

        new_string += string[start_index:end_index]

    return new_string


def is_close(num1, num2):
    # type: (int|long, int|long) -> bool
    """
    Determine whether two numbers represent nearby addresses

    :param num1: First number
    :param num2: Second number
    :return: True if they differ by 255 bytes or fewer, False otherwise
    """
    return abs(num1 - num2) <= 255
