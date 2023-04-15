import traceback

from capstone import *
from elftools.elf.elffile import ELFFile
from .dataset_utils import *

# Only include functions with tokens such that TOKEN_LOWER_BOUND <= tokens <= TOKEN_UPPER_BOUND
TOKEN_UPPER_BOUND = 510
TOKEN_LOWER_BOUND = 5

def get_function_reps(die, calling_context_dict):
    """
    Gets all function representatives of a DWARF Debugging Information Entry (DIE)
    and its children. Builds a list of dictionaries containing the start address, end
    address, and name of each function within the DIE and its children.
    The returned list is of the following format:

        [
            {
                'start_addr': START_ADDRESS,
                'end_addr': END_ADDRESS,
                'name': FUNCTION_NAME
            }
        ]

    :param die: the Debugging Information Entry
    :param calling_context_dict: calling context dictionary (ICFG) of a binary
    :return: list of dictionaries containing each representative function's name and start and end addresses 
    """

    functions = []
    for child_die in die.iter_children():
        # Check if the Debugging Information Entry corresponds to a function/subprogram
        tag_type = child_die.tag.split('_')[-1]
        if tag_type == 'subprogram':
            # Get name, start/end address of the function
            function = {}
            try:
                function['start_addr'] = child_die.attributes['DW_AT_low_pc'][2]
                offset = child_die.attributes['DW_AT_high_pc'][2]
                function['end_addr'] = function['start_addr'] + offset
                function['name'] = child_die.attributes['DW_AT_name'][2].decode('utf-8')

                if function['name'] in calling_context_dict:
                    functions.append(function)
            except KeyError as _:
                print(traceback.format_exc())

    return functions

def create_func_micro_traces(func, func_opcodes, arch, cs_obj):
    """
    Generates function micro-trace sequences for each sequence defined in
    the paper TREX: Learning Execution Semantics from Micro-Traces
    for Binary Similarity.

    https://arxiv.org/pdf/2012.08680.pdf

    The following lists/sequences are returned in one, unified dictionary.
    Keys of the dictionary are the below names, mapped to each corresponding
    micro-trace sequence:
        1.) static: Micro-trace code sequence
        2.) inst_pos: Micro-trace position sequence (Instruction Position Sequence)
        3.) op_pos: Micro-trace position sequence (Opcode/Operand Position Sequence)
        4.) arch: Micro-trace architecture sequence
        5.) byte1, byte2, byte3, byte4

    :param func: single function representative for a Debugging Information Entry (DIE)
    :param func_opcodes: function opcodes
    :param arch: the hardware architecture
    :param cs_obj: Capstone object used for binary disassembly
    :return: dictionary containing micro-trace sequences as defined in the TREX paper
    """

    # Create dictionary of function micro-traces
    micro_traces = {
        'static': [],
        'inst_pos': [],
        'op_pos': [],
        'arch': [],
        'byte1': [],
        'byte2': [],
        'byte3': [],
        'byte4': []
    }

    # Counter used to track instruction position
    inst_pos_counter = 0

    try:
        start_addr = func['start_addr']
        end_addr = func['end_addr']

        # Iterate over all opcodes in the function
        for address, _, op_code, op_str in cs_obj.disasm_lite(func_opcodes, start_addr):
            if address >= end_addr:
                break

            # Tokenize Instruction, add to Micro-Trace Sequences
            if start_addr <= address and address < end_addr:
                tokens = tokenize(f'{op_code} {op_str}')

                for i, token in enumerate(tokens):
                    if '0x' in token.lower():
                        micro_traces['static'].append('hexvar')
                        bytes = hex2seq(token.lower())
                        micro_traces['byte1'].append(bytes[0])
                        micro_traces['byte2'].append(bytes[1])
                        micro_traces['byte3'].append(bytes[2])
                        micro_traces['byte4'].append(bytes[3])

                    elif token.lower().isdigit():
                        micro_traces['static'].append('num')
                        bytes = hex2seq(hex(int(token.lower())))
                        micro_traces['byte1'].append(bytes[0])
                        micro_traces['byte2'].append(bytes[1])
                        micro_traces['byte3'].append(bytes[2])
                        micro_traces['byte4'].append(bytes[3])

                    else:
                        micro_traces['static'].append(token)
                        micro_traces['byte1'].append('##')
                        micro_traces['byte2'].append('##')
                        micro_traces['byte3'].append('##')
                        micro_traces['byte4'].append('##')

                    micro_traces['inst_pos'].append(str(inst_pos_counter))
                    micro_traces['op_pos'].append(str(i))
                    micro_traces['arch'].append(arch)

            inst_pos_counter += 1

    except CsError as e:
        print("[-]", f"ERROR: {e}")

    return micro_traces

def create_micro_trace_dict(input_binary, calling_context_dict, arch, cs_obj):
    """
    Generates function micro-trace sequences for each sequence defined in
    the paper TREX: Learning Execution Semantics from Micro-Traces
    for Binary Similarity. Micro-trace sequences are generated for each function
    that appears in the input binary.

    https://arxiv.org/pdf/2012.08680.pdf

    The following lists/sequences are returned in one, unified dictionary.
    Keys of the dictionary are the below names, mapped to each corresponding
    micro-trace sequence:
        1.) static: Micro-trace code sequence
        2.) inst_pos_emb: Micro-trace position sequence (Instruction Position Sequence)
        3.) op_pos_emb: Micro-trace position sequence (Opcode/Operand Position Sequence)
        4.) arch_emb: Micro-trace architecture sequence
        5.) byte1, byte2, byte3, byte4
        6.) label

    :param input_binary: the name of the binary for which to create micro-traces
    :param calling_context_dict: calling context dictionary (ICFG) for the input binary
    :param arch: the hardware architecture
    :param cs_obj: Capstone object used for binary disassembly
    :return: dictionary containing micro-trace sequences as defined in the TREX paper
    """

    micro_trace_dict = {}
    with open(input_binary, 'rb') as bin:
        elffile = ELFFile(bin)
        dwarf = elffile.get_dwarf_info()

        # Disassemble the Byte Code with Capstone
        code = elffile.get_section_by_name('.text')
        opcodes = code.data()
        addr = code['sh_addr']

        for CU in dwarf.iter_CUs():
            function_reps = get_function_reps(CU.get_top_DIE(), calling_context_dict)

            # Generate Micro-trace sequences for each representative function
            for func in function_reps:
                start_addr = func['start_addr']
                func_opcodes = opcodes[start_addr-addr:]

                micro_traces = create_func_micro_traces(func, func_opcodes, arch, cs_obj)
                static = micro_traces['static']
                inst_pos = micro_traces['inst_pos']
                op_pos = micro_traces['op_pos']
                arch_emb = micro_traces['arch']
                byte1 = micro_traces['byte1']
                byte2 = micro_traces['byte2']
                byte3 = micro_traces['byte3']
                byte4 = micro_traces['byte4']
                preprocessed_name = func_name_preprocessing(func['name'])

                # Skip functions with too many tokens or too few tokens
                if len(inst_pos) > TOKEN_UPPER_BOUND or len(inst_pos) < TOKEN_LOWER_BOUND:
                    continue

                if preprocessed_name is None:
                    continue

                micro_trace_dict[func['name']] = {
                    'static': ' '.join(static), 
                    'inst_pos_emb': ' '.join(inst_pos), 
                    'op_pos_emb': ' '.join(op_pos), 
                    'arch_emb': ' '.join(arch_emb), 
                    'byte1': ' '.join(byte1), 
                    'byte2': ' '.join(byte2), 
                    'byte3': ' '.join(byte3), 
                    'byte4': ' '.join(byte4), 
                    'label': preprocessed_name
                }

    return micro_trace_dict
