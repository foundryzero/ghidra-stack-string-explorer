"""
Simulator
Simulates all instructions then extracts strings from any memory that is modified
"""

from __main__ import getFunctionContaining

from technique import Technique
from specific_utilities import (
    decode_as_key_offset,
    convert_string_to_num,
    convert_num_to_string,
    initial_to_key_offset,
    get_default,
    is_string,
    find_index_of_similar_scalar,
)
from general_utilities import reorder, replace_section
from abstract_address import AbstractAddress
from stack_string import StackString
from stack_strings_enums import KnownStatus


try:
    # Typing information for VSCode - Ghidra will not load this section
    # Requires ghidra_stubs from https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator
    import typing

    if typing.TYPE_CHECKING:
        from typing import List, Tuple, Dict, Any
        from ghidra.program.model.listing import Instruction
        from ghidra.program.model.pcode import PcodeOp, Varnode

        from long import long

        # pylint: disable=pointless-statement
        long

# pylint: disable=bare-except
except:
    pass


class Simulator(Technique):
    """
    Simulates pcode instructions for the sake of extracting stack strings
    """

    locations = {}  # type: Dict[str, Dict[str|long, Any]]
    reverse = False
    discarded_strings = []  # type: List[StackString]
    min_length = 0
    address_filtering_intensity = None  # type: str

    def __init__(self, reverse, min_length, address_filtering_intensity):
        # type: (bool, int, str) -> None
        """
        :param reverse: if True, strings components are compiled from low offset to high, if False
        string components are compiled from high offset to low.
        :param min_length: The minimum length of a string to look for
        :param address_filtering_intensity: The degree to which strings that look like addresses
        should be removed

        Locations:
        A dictionary.
        **keys** - must be strings. Represent a unique id for describing that way of accessing some
        memory offset
        e.g. the values stored at some offset to the initial value of varnode (register, 0x20, 8)
        would have key "[INIT: (register:, 32)]".
        Address spaces within the ghidra varnodes also have their own keys e.g. "unique:"

        Special keys: These are not considered contiguous memory. Strings are extracted differently
        from these address spaces.
            - 'mappings:' - not accessed by instructions. Used at the end to map INIT and RESET
            strings to concrete possible values inferred by comparisons. The keys are INIT and
            RESET strings and the values are lists of possible concrete values.
            - 'registers:' - an address space from varnodes that stores all registers. Strings in
            adjacently numbered registers are not concatenated together.
            - 'const:' - an address space from varnodes that stores constant values. This should not
            be included in the dictionary as it is never stored to.


        **values** - a dictionary.
            keys - must be integers. Represent offsets from the parent key at which values are
            stored
            values - can be one of a few types
                - StackString: a stack string is stored directly at this location
                - long: a number is stored directly at this location
                - AbstractAddress: the value stored at this location has been constructed by
                addressing memory that we don't know the value of. The value is tracked as if
                it represents an address as we have no other need for unknown values
                - list: this is used only for 'mappings:'. The list can hold different values
                    - StackString: a string is a possible initial value for this key
                    - long: a long is a possible initial value for this key
                    - AbstractAddress: the abstract address has operation BASE and represents the
                    initial or reset value of a location. In a mappings list it means the initial
                    value of the mapping key could also be any of the initial values of this new
                    location.
        """
        self.locations = {}
        self.reverse = reverse
        self.discarded_strings = []
        self.min_length = min_length
        self.address_filtering_intensity = address_filtering_intensity

    def get_value(
        self,
        key,  # type: str
        offset,  # type: long|str
    ):
        # type: (...) -> StackString|long|AbstractAddress|List[StackString|long|AbstractAddress]
        """
        Retrieves the value at the location described by key and offset, or the default initial
        value if none is stored

        :param key: The address space to be fetched from
        :param offset: The offset into the address space to be fetched from
        :return: The value stored at the address
        """

        if key in self.locations and offset in self.locations[key]:
            return self.locations[key][offset]

        return AbstractAddress(get_default(key, offset))

    def get_value_varnode(self, var_node, op, instruction):
        # type: (Varnode, PcodeOp, Instruction) -> StackString|long|AbstractAddress
        """
        Returns the value stored at a varnode
        Differs only from get_value if the varnode is constant and not already seen

        :param var_node: The varnode describing the location to be fetched from
        :param op: The operation that this varnode comes from in case a StackString must be created
        :param instruction: The instruction that op comes from in case a StackString must be created
        """
        address = var_node.getAddress()
        offset = address.getOffset()
        key = str(address.getAddressSpace())
        return_value = None

        if var_node.isConstant() and (
            key not in self.locations or offset not in self.locations[key]
        ):
            string = convert_num_to_string(offset)

            # if the constant is likely a string, return it as a string
            if is_string(string, op, instruction, self.address_filtering_intensity):
                index = find_index_of_similar_scalar(string, instruction)
                return_value = StackString(string, instruction, index)
            else:
                # otherwise return the numerical value
                return_value = offset
        else:
            return_value = self.get_value(key, offset)

        return return_value

    def __known_status(self, value):
        # type: (StackString|long|AbstractAddress) -> str
        """
        Determines the known status of a value

        known - StackString or long
        unknown - Component with multiple components or non-zero offset
        unifiable - Component with single component and zero offset - an INIT value
        unified - a unifiable that has already been unified once

        :param value: the value
        :return: a string describing the known status of the value
        """
        if isinstance(value, StackString):
            return KnownStatus.STRING

        if isinstance(value, long):
            return KnownStatus.NUM

        if "mappings:" in self.locations and str(value) in self.locations["mappings:"]:
            return KnownStatus.UNIFIED

        if len(value.components) == 1 and value.offset == 0:
            return KnownStatus.UNIFIABLE

        return KnownStatus.UNKNOWN

    def __set_location(
        self,
        key,  # type: str
        offset,  # type: long|str
        val,  # type: StackString|long|AbstractAddress|List[StackString|long|AbstractAddress]
    ):
        # type: (...) -> None
        """
        Sets the location described by key and offset to val, validates type of val
        Centralizes accesses to locations

        :param key: The address space of the location to be modified
        :param offset: The offset into the address space of the location to be modified
        :param val: The value to set the location to
        :param check: Whether to check the type of val
        """

        if key in self.locations and offset in self.locations[key]:
            value = self.locations[key][offset]
            if isinstance(value, StackString) and value not in self.discarded_strings:
                # if a string is being replaced, keep track of it
                self.discarded_strings.append(value)
        elif key not in self.locations:
            # create a key if it doesn't already exist
            self.locations[key] = {}

        self.locations[key][offset] = val

    def __add_default(self, key, offset):
        # type: (str, long) -> None
        """
        Adds the default initial value to the location described by key and offset

        :param key: The address space of the value to be set
        :param offset: The offset into the address space of the value to be set
        """
        if key not in self.locations:
            self.locations[key] = {}

        if offset not in self.locations[key]:
            val = get_default(key, offset)
            self.__set_location(key, offset, AbstractAddress(val))

    def __move(
        self,
        source,  # type: StackString|long|AbstractAddress|List[StackString|long|AbstractAddress]
        dest,  # type: Varnode
    ):
        # type: (...) -> None
        """
        Moves a source value into a destination varnode

        :param source: Value to be stored e.g. StackString/long/AbstractAddress
        :param dest: Varnode to store to
        """
        dest_address = dest.getAddress()
        dest_offset = dest_address.getOffset()
        dest_key = dest_address.getAddressSpace().toString()
        self.__set_location(dest_key, dest_offset, source)

    def __copy(self, inputs, output):
        # type: (List[StackString|long|AbstractAddress], Varnode) -> None
        """
        Handles COPY instruction
        e.g. (register, 0x10, 8) COPY (const, 0x102010, 8)
        Meaning: copy the value 0x102010 into register 0x10
        inputs - [0x102010]
        output - (register, 0x10, 8)

        :param inputs: Inputs values to COPY
        :param output: Output varnode of COPY
        """
        input0 = inputs[0]
        self.__move(input0, output)

    def __store(self, inputs):
        # type: (List[StackString|long|AbstractAddress]) -> None
        """
        Handles STORE instruction
        e.g.  ---  STORE (const, 0x1b1, 8) , (register, 0x20, 8) , (const, 0x10137d, 8)
        Meaning: store the value 0x102010 into the location addressed by the value of register 0x20
        inputs - [0x1b1, Locations['register:'][0x20], 0x10137d]

        :param inputs: Inputs values to STORE
        """
        input1 = inputs[1]
        input2 = inputs[2]

        key, offset = decode_as_key_offset(input1)

        if key is None or offset is None:
            print("location unknown: " + str(input1))
            return

        self.__set_location(key, offset, input2)

    def __load(self, inputs, output):
        # type: (List[StackString|long|AbstractAddress], Varnode) -> None
        """
        Handles LOAD instruction
        e.g. (register, 0x288, 8) LOAD (const, 0x1b1, 8) , (register, 0x20, 8)
        Meaning: load the value from the location addressed by the value of register 0x20
        and store it in register 0x288
        inputs - [0x1b1, Locations['register:'][0x20]]
        output - (register, 0x288, 8)

        :param inputs: Inputs values to LOAD
        :param output: Output varnode of LOAD
        """
        input1 = inputs[1]
        key, offset = decode_as_key_offset(input1)

        if key is None or offset is None:
            print("location unknown: " + str(input1))
            return

        val = self.get_value(key, offset)
        self.__move(val, output)

    def __add(self, inputs, output):
        # type: (List[StackString|long|AbstractAddress], Varnode) -> None
        """
        Handles INT_ADD instruction
        e.g. (register, 0x20, 8) INT_ADD (register, 0x20, 8) , (const, 0x8, 8)
        Meaning: add 8 to the value stored in register 0x20 then store the result back to
        register 0x20
        inputs - [Locations['register:'][0x20], 8]
        output - (register, 0x20, 8)

        :param inputs: Inputs values to INT_ADD
        :param output: Output varnode of INT_ADD
        """
        input0 = inputs[0]
        input1 = inputs[1]

        if isinstance(input0, StackString):
            input0 = long(convert_string_to_num(input0.get_string()))

        if isinstance(input1, StackString):
            input1 = long(convert_string_to_num(input1.get_string()))

        if isinstance(input0, long) and isinstance(input1, long):
            val = input0 + input1  # type: long | AbstractAddress

        elif isinstance(input0, long) and isinstance(input1, AbstractAddress):
            new1 = input1.get_copy()
            new1.offset += input0
            val = new1

        elif isinstance(input0, AbstractAddress) and isinstance(input1, long):
            new0 = input0.get_copy()
            new0.offset += input1
            val = new0

        else:
            components = []  # type: List [str|long|AbstractAddress]

            if input0.op == AbstractAddress.Operation.ADD:
                components.extend(input0.components)
            else:
                new0 = input0.get_copy()
                new0.offset = 0
                components.append(new0)

            if input1.op == AbstractAddress.Operation.ADD:
                components.extend(input1.components)
            else:
                new1 = input1.get_copy()
                new1.offset = 0
                components.append(new1)

            offset = input0.get_offset() + input1.get_offset()

            val = AbstractAddress(components, AbstractAddress.Operation.ADD, offset)
        self.__move(val, output)

    def __mult(self, inputs, output):
        # type: (List[StackString|long|AbstractAddress], Varnode) -> None
        """
        Handles INT_MULT instruction
        e.g. (unique, 0x3a00, 4) INT_MULT (register, 0x8, 4) , (const, 0x4, 4)
        Meaning: multiply the value stored in register 0x8 by 4 then store the result to the unique
        address space at offset 0x3a00
        inputs - [Locations['register:'][0x8], 4]
        output - (unique, 0x3a00, 4)

        :param inputs: Inputs values to INT_MULT
        :param output: Output varnode of INT_MULT
        """
        input0 = inputs[0]
        input1 = inputs[1]

        if isinstance(input0, StackString):
            input0 = long(convert_string_to_num(input0.get_string()))

        if isinstance(input1, StackString):
            input1 = long(convert_string_to_num(input1.get_string()))

        if isinstance(input0, long) and isinstance(input1, long):
            val = input0 * input1  # type: long | AbstractAddress

        else:
            components = []  # type: List[str | long | AbstractAddress]

            if isinstance(input0, long):
                components.append(input0)
            elif input0.op == AbstractAddress.Operation.MULTIPLY and input0.offset == 0:
                components.extend(input0.components)
            else:
                new0 = input0.get_copy()
                components.append(new0)

            if isinstance(input1, long):
                components.append(input1)
            elif input1.op == AbstractAddress.Operation.MULTIPLY and input1.offset == 0:
                components.extend(input1.components)
            else:
                new1 = input1.get_copy()
                components.append(new1)

            val = AbstractAddress(
                components, AbstractAddress.Operation.MULTIPLY, long(0)
            )

        self.__move(val, output)

    def __compare(self, inputs, input_locations):
        # type: (List[StackString|long|AbstractAddress], List[Varnode]) -> None
        """
        Handles INT_LESS instruction
        e.g. (register, 0x200, 1) INT_LESS (unique, 0x27180, 4) , (const, 0x6968, 4)
        Meaning: store the binary outcome of the comparison between the value stored
        in the unique address space at offset 0x27180 and 0x6968 into register 0x200
        inputs - [Locations['unique:',0x27180 ], 0x6968]
        input_locations - [(unique, 0x27180, 4) , (const, 0x6968, 4)]

        Simplified compare that infers the values of the inputs as the same, and does
        not handle the output.

        known known - do nothing
        known unknown - do nothing
        known unifiable - store unifiable -> [known]
        known unified - update unified.append[known]

        unknown unknown - do nothing
        unknown unifiable - do nothing
        unknown unified - do nothing

        unifiable unifiable - store unifiable -> [unifiable]
        unifiable unified - store unifiable -> [unified], update unified.append(unifiable)

        unified unified - update unified.append(unifiable)

        :param inputs: Input values to INT_LESS
        :param input_locations: Input varnodes to INT_LESS
        """
        input0 = inputs[0]
        input1 = inputs[1]

        key = "mappings:"

        if key not in self.locations:
            self.locations[key] = {}

        status0 = self.__known_status(input0)
        status1 = self.__known_status(input1)

        # unknown *
        if status0 == KnownStatus.UNKNOWN or status1 == KnownStatus.UNKNOWN:
            return

        # unifiable * and unified *
        offset = str(input0)

        if status0 == KnownStatus.UNIFIABLE:
            # set the mapping
            self.__set_location(key, offset, [input1])

            # set the default value now that mapping is known
            initial_key, initial_offset = initial_to_key_offset(input0.components[0])
            self.__add_default(initial_key, initial_offset)

        elif status0 == KnownStatus.UNIFIED:
            # set the mapping
            self.locations[key][offset].append(input1)

        offset = str(input1)

        if status1 == KnownStatus.UNIFIABLE:
            # set the mapping
            self.__set_location(key, offset, [input0])

            # set the default value now that mapping is known
            initial_key, initial_offset = initial_to_key_offset(input1.components[0])
            self.__add_default(initial_key, initial_offset)

        elif status1 == KnownStatus.UNIFIED:
            self.locations[key][offset].append(input0)

        # if num is compared against string, then something has likely gone wrong
        # in resetting one of the arguments. We do not recover completely from
        # this, instead perform best effort in resetting at point of comparison.
        # This leaves open failure cases where the value should have been reset
        # earlier and has been copied to this location. The original will not
        # know that it should take the new string value.
        # The same is true for num num and string string, but we do nothing
        # to recover from these.
        if (
            status0 == KnownStatus.NUM
            and status1 == KnownStatus.STRING
            and not input_locations[0].isConstant()
        ):
            self.__move(input1, input_locations[0])

        if (
            status1 == KnownStatus.NUM
            and status0 == KnownStatus.STRING
            and not input_locations[1].isConstant()
        ):
            self.__move(input0, input_locations[1])

    def __kill(self, var_node, unique_id):
        # type: (Varnode, Any) -> None
        """
        Resets a location to a new abstract value

        :param var_node: The varnode of the location to be reset
        :param unique_id: Combines with the varnode to form a unique id of this reset value
        """

        if var_node:
            address = var_node.getAddress()
            offset = address.getOffset()
            key = str(address.getAddressSpace())

            self.__set_location(
                key,
                offset,
                AbstractAddress(
                    "RESET: " + key + ", " + str(unique_id) + ", " + str(offset)
                ),
            )

    def __call(self, inputs, call_id):
        # type: (List[Varnode], Any) -> None
        """
        Handles CALL instruction
        e.g.  ---  CALL (ram, 0x101090, 8)
        Meaning: call the function found at offset 0x101090 in ram
        inputs - (ram, 0x101090, 8)

        Re-initializes any inputs we know are overwritten, or are definitely addresses

        :param inputs: Inputs varnodes to CALL
        :param call_id: Unique id for this call for reset values
        """
        input0 = inputs[0]
        self.__kill(input0, call_id)

        f = getFunctionContaining(input0.getAddress())
        if f is None:
            return

        var_node = f.getReturn().getLastStorageVarnode()
        self.__kill(var_node, call_id)

        calling_convention = f.getCallingConvention()
        if calling_convention is None:
            return

        killed = calling_convention.getKilledByCallList()

        for var_node in killed:
            self.__kill(var_node, call_id)

    def __get_inputs(self, op, inst):
        # type: (PcodeOp, Instruction) -> List[StackString|long|AbstractAddress]
        """
        Gets the values stored in locations or the default values for all inputs in an operation

        :param op: The operation containing inputs to be fetched
        :param inst: The instruction this operation comes from
        """

        inputs = []

        # get each input varnode
        for i in range(0, op.getNumInputs()):
            in_var_node = op.getInput(i)

            val = self.get_value_varnode(in_var_node, op, inst)
            inputs.append(val)

        return inputs

    def __fetch_all_from_match(
        self,
        match_list,  # type: List[StackString|long|AbstractAddress]
        visited,  # type: List[StackString|long|AbstractAddress]
    ):
        # type: (...) -> List[StackString|long|AbstractAddress]
        """
        Fetches all strings associated with a list of values recursively

        :param match_list: The list of components to match
        :param visited: The list of already identified components
        :return: If visited == [], then a list of compiled stack strings.
        Otherwise a list of compiled components.

        For each match, if it is a concrete value (a StackString) then add
        it to the result of possible initial values.
        If it is a non-concrete value that also has a mappings: entry, then
        recursively search that mappings: entry for other possible values.
        Exclude in the recursive search any mappings: keys we have already
        searched to avoid loops. We also exclude any strings we have already
        seen to avoid duplicates.
        If this is the top level, then return only the matched strings.
        If this is a recursive level, then return the matched strings and any
        visited keys.
        """
        # take a shallow copy of the visited list
        matched_strings = visited[:]

        for match in match_list:
            if match not in matched_strings:
                known = self.__known_status(match)
                # ignore numbers and unknown initial/reset values
                if known == KnownStatus.STRING:
                    matched_strings.append(match)
                if known == KnownStatus.UNIFIED:
                    matched_strings.append(match)

                    new_match_list = self.get_value("mappings:", str(match))

                    matched_strings = self.__fetch_all_from_match(
                        new_match_list, matched_strings
                    )

        if visited == []:
            # filter out key names from the exclude list to leave only the matched strings
            matched_strings = [
                string for string in matched_strings if isinstance(string, StackString)
            ]
        return matched_strings

    def __prepare(self, min_length):
        # type: (int) -> Tuple[Dict[str, Dict[long, Any]], List[StackString]]
        """
        Prepares the locations for decoding. Pushes through any mappings into locations
        that have the corresponding initial and decides any ambiguity.

        :param min_length: the minimum length of string to look for
        :return: A two element tuple containing:
        1. A list of StackStrings discarded during preparation
        2. The prepared dictionary
        """
        discarded_string_parts = []

        # take a shallow copy - we can pop address spaces without modifying
        # locations, but changes to address spaces will propagate.
        search_space = self.locations.copy()

        # Make sure all mapping values are added as discarded
        # This should be fully covered by the next block, but as a failsafe
        if "mappings:" in search_space:
            for value_list in search_space["mappings:"].values():
                for value in value_list:
                    if isinstance(value, StackString) and len(value) > min_length:
                        discarded_string_parts.append(value)
            search_space.pop("mappings:")

        # push through mappings and remove ambiguity
        for address_space in search_space.values():
            for offset in address_space.keys():
                value = address_space[offset]

                # if the value represents an initial value that is now known,
                # replace it with all possible strings
                if self.__known_status(value) == KnownStatus.UNIFIED:
                    match_list = self.locations["mappings:"][str(value)]
                    address_space[offset] = self.__fetch_all_from_match(match_list, [])
                    value = address_space[offset]

                # if after loading from mappings: there are multiple options, disambiguate
                if isinstance(value, list) and value != []:

                    # select the longest string
                    value.sort(key=len, reverse=True)
                    address_space[offset] = value[0]

                    # if there is ambiguity, add all longer strings to the discarded list
                    discarded_string_parts.extend(
                        [
                            stack_string
                            for stack_string in value[1:]
                            if stack_string not in discarded_string_parts
                            and len(stack_string) >= min_length
                        ]
                    )

        # Add all register values as discarded - memory is non-contiguous so must be removed
        if "register:" in search_space:
            for value in search_space["register:"].values():
                if isinstance(value, StackString) and len(value) > min_length:
                    discarded_string_parts.append(value)

            search_space.pop("register:")

        return search_space, discarded_string_parts

    def get_strings(self):
        # type: () -> List[StackString]
        """
        Decodes locations into any consecutive strings

        :return: A list compiled StackStrings
        """
        search_space, discarded_strings_from_prepare = self.__prepare(self.min_length)
        strings = set(
            discarded_strings_from_prepare
            + [
                string
                for string in self.discarded_strings
                if len(string) >= self.min_length
            ]
        )
        parts_used = strings.copy()
        parts_in_use = []  # type: List[StackString]

        for address_space in search_space.values():
            current_string = ""
            components_start_indexes = []  # type: List[int]

            offsets = list(address_space.keys())

            offsets.sort()

            previous_offset = None
            last_instruction = None  # type: Instruction
            last_index = None  # type: int

            for offset in offsets:
                value = address_space[offset]

                # if the value is not a stack string, then discard it
                if not isinstance(value, StackString):
                    continue

                # get initial values if this is the first string in the address space
                if previous_offset is None:
                    previous_offset = offset
                    # expected address of next character
                    expected = offset
                    # the offset that creates the start of the string
                    string_start_offset = offset

                if last_instruction is None:
                    last_instruction = value.get_instruction()

                if last_index is None:
                    last_index = value.get_index()

                # if the next offset is further than expected, terminate the previous string
                if offset > expected:

                    if self.reverse:
                        current_string = reorder(
                            current_string, components_start_indexes
                        )

                    # if the string was long enough, then record it
                    if len(current_string) >= self.min_length:
                        stack_string = StackString(
                            current_string, last_instruction, last_index
                        )
                        # do not record it if the string has been seen before, or is a single
                        # string part that has already been used in a different string
                        if (
                            stack_string not in strings
                            and stack_string not in parts_used
                        ):
                            strings.add(stack_string)
                            parts_used.update(parts_in_use)
                            parts_in_use = []

                    expected = offset
                    string_start_offset = offset
                    last_instruction = value.get_instruction()
                    last_index = value.get_index()
                    current_string = ""
                    components_start_indexes = []

                # if the string part has been added by itself previously, remove it
                # as this will either re-add it individually, or as part of a longer string
                if value in strings:
                    strings.remove(value)
                    parts_used.remove(value)

                to_insert_start_index = offset - string_start_offset
                to_insert = value.get_string()

                # place the string into the string being constructed at the right index
                current_string = replace_section(
                    current_string, to_insert, to_insert_start_index
                )

                # keep track of index into string each new component is put at
                if offset == expected:
                    components_start_indexes.append(to_insert_start_index)

                expected = string_start_offset + len(current_string)
                previous_offset = offset
                parts_in_use.append(value)
                if self.reverse:
                    last_instruction = value.get_instruction()
                    last_index = value.get_index()

            # terminate the final string if it meets the requirements
            if self.reverse:
                current_string = reorder(current_string, components_start_indexes)

            if len(current_string) >= self.min_length:
                stack_string = StackString(current_string, last_instruction, last_index)
                # do not record it if the string has been seen before, or is a single
                # string part that has already been used in a different string
                if stack_string not in strings and stack_string not in parts_used:
                    strings.add(stack_string)
                    parts_used.update(parts_in_use)
                    parts_in_use = []

        return list(strings)

    def run(self, inst, op):
        # type: (Instruction, PcodeOp) -> None
        """
        Run a pcode operation in the simulator

        :param inst: The instruction the pcode operation is a part of
        :param op: The pcode operation to run
        """
        inputs = self.__get_inputs(op, inst)
        output = op.getOutput()
        opcode = op.getOpcode()

        if opcode in (op.COPY, op.INT_ZEXT, op.INT_SEXT):
            self.__copy(inputs, output)

        elif opcode == op.LOAD:
            self.__load(inputs, output)

        elif opcode == op.STORE:
            self.__store(inputs)

        elif opcode == op.INT_ADD:
            self.__add(inputs, output)

        elif opcode == op.INT_MULT:
            self.__mult(inputs, output)

        elif opcode == op.INT_LESS:
            self.__compare(inputs, op.getInputs())

        elif opcode == op.CALL:
            self.__call(op.getInputs(), inst.getAddress())

    def reset(self):
        # type: () -> None
        """
        Reset the simulator
        """
        self.locations = {}
        self.discarded_strings = []

    def end_function(self):
        # type: () -> None
        """
        Performs processing when a function finishes

        The simulator does no additional processing when a function ends
        """
