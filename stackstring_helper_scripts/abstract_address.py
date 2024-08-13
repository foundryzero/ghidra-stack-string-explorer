"""
AbstractAddress
Encapsulates the information needed about a value stored in memory that is not fully known
"""

try:
    # Typing information for VSCode - Ghidra will not load this section
    # Requires ghidra_stubs from https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    import typing

    if typing.TYPE_CHECKING:
        from typing import List
        from long import long

        # pylint: disable=pointless-statement
        long

# pylint: disable=bare-except
except:
    pass


# # Globals
# Cap on the number of components we will continue to track in an abstract address
# to reduce memory use in large functions
MAX_COMPONENT_NUMBER = 100


class AbstractAddress:
    """
    A value representing an address stored in memory.
    The address may rely on values that are unknown in the simulated region,
    but addresses that are close to each other should be able to be identified as such.
    An AbstractAddress has an operation and some components, the meaning of which varies
    depending on the operation:
    BASE - a single string component representing an unknown value e.g. 'INIT: register:, 32'
    meaning the initial value stored in 'register:' 32
    ADD - the components are other AbstractAddresses that sum to give the overall address
    MULTIPLY - the components are other AbstractAddresses or numbers that multiply to give the
    overall address

    Performing this processing of components gives a key representing the 'address space' the
    AbstractAddress refers to.
    Each AbstractAddress also has a numerical offset which is added to the key to give the overall
    address.
    The split into key/offset allows different AbstractAddresses with the same key and
    different offsets to reference memory locations that are considered near each other.

    Example:
    op - BASE
    Components - ['INIT: register:, 32']
    Offset - 0
    MEANING: the value initially in register 32
    ---------------------------------------------
    op - BASE
    Components - ['INIT: register:, 32']
    Offset - 4
    MEANING: the value initially in register 32 plus 4

    If these two AbstractAddresses are stored to then we know they reference memory 4 bytes apart,
    despite not knowing what the original value of register 32 is.
    The values assigned to them would be stored in a Locations dictionary in address space
    "[INIT: register:, 32]" with offsets 0 and 4 respectively.

    Everything that is not a known string or integer is treated as if it is an address, so many
    AbstractAddress objects may track values in the binary which are never treated as an address.
    """

    components = []  # type: List[str|long|AbstractAddress]
    offset = long(0)
    op = None  # type: str

    class Operation:
        """
        An Enum for AbstractAddress operations
        """

        BASE = "base"
        ADD = "add"
        MULTIPLY = "mult"

    def __init__(self, components, operation=Operation.BASE, offset=long(0)):
        # type: (List [str|long|AbstractAddress] | str, str, long) -> None

        if isinstance(components, str):
            self.components = [components]
        else:
            self.components = components[:MAX_COMPONENT_NUMBER]

        self.op = operation
        self.offset = offset

    def _get_key_as_string(self):
        # type: (AbstractAddress) -> str
        """
        Creates a string representation of the key by adding the operation between components
        Only prints the first three components to avoid excessively long strings

        :return: The processed string
        """
        components_as_strings = list(
            map(lambda x: "(" + str(x) + ")", self.components[:3])
        )

        if len(self.components) > 3:
            components_as_strings.append("...")

        return (" " + str(self.op) + " ").join(components_as_strings)

    def __str__(self):
        string = self._get_key_as_string()
        if self.offset != 0:
            string += " add " + str(self.offset)
        return string

    def __repr__(self):
        return self.__str__()

    def get_key(self):
        # type: (AbstractAddress) -> str
        """
        Retrieve the string representation of the key

        :return: The key string
        """
        return self._get_key_as_string()

    def get_offset(self):
        # type: (AbstractAddress) -> long
        """
        Retrieve the numerical offset

        :return: The offset number
        """
        return self.offset

    def get_copy(self):
        # type(AbstractAddress) -> AbstractAddress
        """
        Shallow copies this Component object

        :return: The shallow copy
        """
        return AbstractAddress(self.components, self.op, self.offset)
