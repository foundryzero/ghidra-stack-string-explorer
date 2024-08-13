"""
Specific Utilities
Stores functions that are specific to the classes and types used in the StackStringExplorer program
"""

from abstract_address import AbstractAddress
from stack_strings_enums import AddressFilteringIntensity
from stack_string import StackString
from general_utilities import convert_num_to_string, convert_string_to_num, is_close

from ghidra.program.model.lang import OperandType

try:
    # Typing information for VSCode - Ghidra will not load this section
    # Requires ghidra_stubs from https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    import typing

    if typing.TYPE_CHECKING:
        from typing import List, Tuple, Any

        from ghidra.program.model.listing import Instruction
        from ghidra.program.model.pcode import PcodeOp
        from parameters import Parameters

        from long import long

        # pylint: disable=pointless-statement
        long

# pylint: disable=bare-except
except:
    pass


def check_parameters(params):
    # type: (Parameters) -> None
    """
    Ensures given parameters are in the correct ranges

    :param params: The parameters to be checked
    :raises ValueError: Raises error if the parameters are invalid
    """
    if (
        isinstance(params.min_length, int)
        and isinstance(params.look_ahead, int)
        and isinstance(params.len_of_interest, int)
        and (isinstance(params.domain, unicode) or isinstance(params.domain, str))
        and isinstance(params.reverse, bool)
        and (
            isinstance(params.address_filtering_intensity, unicode)
            or isinstance(params.address_filtering_intensity, str)
        )
        and params.min_length > 0
        and params.look_ahead > 0
        and params.len_of_interest > 0
    ):
        return
    raise ValueError("Invalid Parameters")


def is_arithmetic(op):
    # type: (PcodeOp) -> bool
    """
    Determines whether a pcode operation is arithmetic and therefore unlikely to
    use string constants

    :param op: The pcode operation
    :return: True if the operation is an integer addition or subtraction and False otherwise
    """
    m = op.getOpcode()
    return m in (
        op.INT_ADD,
        op.INT_SUB,
        op.INT_DIV,
        op.INT_MULT,
        op.FLOAT_ADD,
        op.FLOAT_SUB,
        op.FLOAT_DIV,
        op.FLOAT_MULT,
    )


def find_index_of_similar_scalar(string, instruction):
    # type: (str, Instruction) -> int
    """
    Finds the index of the operand to instruction that resembles a string found in pcode
    Returns one greater than the number of operands if no similar source is found
    If a reference is made to the found index it will replace the correct operand or if
    there is no correct operand then the reference will still exist to the right instruction

    :param string: The found string
    :param instruction: The instruction the string was found in
    :return: The index of the appropriate operand
    """
    num_operands = instruction.getNumOperands()
    index = num_operands + 1
    for i in range(num_operands):
        if OperandType.isScalar(instruction.getOperandType(i)):
            if (
                convert_string_to_num(string)
                == instruction.getScalar(i).getUnsignedValue()
            ):
                index = i

    return index


# Valid String discovery


def is_string(constant, op, inst, address_filter_intensity):
    # type: (Any, PcodeOp, Instruction, str) -> bool
    """
    Determines if a constant is likely to be a string of interest

    To be considered a string it must:
    - Be a python string
    - Not be part of an arithmetic operation unlikely to be done on strings
    - if SOME: Differ by more than one character to the address of the current instruction
    - if ALL: Not be the same as any address used in the instruction

    :param constant: the potential string
    :param op: the pcode operation the constant was extracted from
    :param inst: the instruction the pcode operation belongs to
    :param address_filtering_intensity: how strictly strings that may be addresses are filtered
    :return: True if the constant is a string, False otherwise
    """
    if isinstance(constant, str) and not is_arithmetic(op):
        if address_filter_intensity == AddressFilteringIntensity.NONE:
            return True

        as_number = convert_string_to_num(constant)
        if not is_close(as_number, inst.getAddress().getOffset()):
            if address_filter_intensity == AddressFilteringIntensity.SOME:
                return True

            for i in range(inst.getNumOperands()):
                if OperandType.isAddress(inst.getOperandType(i)):
                    address = inst.getAddress(i).getOffset()
                    if as_number == address:
                        return False

            if address_filter_intensity == AddressFilteringIntensity.ALL:
                return True
    return False


def get_strings(
    op,  # type: PcodeOp
    inst,  # type: Instruction
    count,  # type: int
    exclusive,  # type: List[str]
    len_of_interest,  # type: int
    address_filtering_intensity,  # type: str
):
    # type: (...) -> List[str]
    """
    Decodes the string constants used as inputs to an operation

    To be considered a string it must:
    - Be made of all printable characters
    - If the count is greater than 4, then it must be longer than 1 character
    - Not be in the excluded list
    - Not be part of an arithmetic operation unlikely to be done on strings
    - Differ by more than one character to the address of the current instruction

    :param op: the pcode operation to extract constants from
    :param count: the number of instructions since the last string component, used
    to identify how likely the constant is to be a string
    :param exclusive: strings to avoid returning, used to avoid reporting the same
    string used by multiple pcode operations within the same overall instruction
    :param inst: the instruction this pcode operation is a part of, used to identify
    how likely the constant is to be a string
    :param len_of_interest: the minimum length of string moved for the instruction to be of interest
    :param address_filtering_intensity: how strictly strings that may be addresses are filtered
    :return: a list of strings extracted from the operation
    """
    strings = []
    # get each input varnode
    for i in range(0, op.getNumInputs()):
        in_var_node = op.getInput(i)

        if in_var_node.isConstant():
            string = convert_num_to_string(in_var_node.getAddress().getOffset())
            if (
                is_string(string, op, inst, address_filtering_intensity)
                and (len(string) >= len_of_interest or count < 4)
                and string not in exclusive
            ):
                strings.append(string)

    return strings


# Key, Offset manipulation


def decode_as_key_offset(value):
    # type: (StackString|long|AbstractAddress) -> Tuple[str, long]
    """
    Takes a value stored at some location and decodes it into a namespace and
    offset as if it were an address.

    :param value: the value to be decoded
    :return: a two element tuple containing:
    1. A string describing the address space
    2. An integer describing the offset into the address space
    """

    key, offset = None, None

    if isinstance(value, AbstractAddress):
        key = "[" + value.get_key() + "]"
        offset = value.get_offset()

    elif isinstance(value, StackString):
        key = "__general__"
        offset = long(convert_string_to_num(value.get_string()))

    elif isinstance(value, long):
        key = "__general__"
        offset = value

    return key, offset


def initial_to_key_offset(INIT_string):
    # type: (str) -> Tuple[str, long]
    """
    Decodes an initial value into the key, offset of the location it references

    :param INIT_string: a string representing the unknown initial value of a location
    :return: a two element tuple containing:
    1. A string describing the address space
    2. An integer describing the offset into the address space
    """
    without_init = INIT_string[6:]
    split = without_init.split(", ")
    offset = long(split[-1])
    key = ", ".join(split[:-1])
    return key, offset


def get_default(key, offset):
    # type: (str, long) -> str
    """
    Returns the string representing the default value for this key and offset

    :param key: a string describing the address space
    :param offset: an integer describing the offset into the address space
    :return: a string representing the unknown initial value of the location
    """
    return "INIT: " + key + ", " + str(offset)
