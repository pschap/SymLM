import json
import argparse
import os
import re
from pathlib import Path
import pyhidra

"""
Get callers and callees of binary functions.
The output is a JSON file in the format of:

    {
        func_name:
        {
            'caller': [],
            'callee': []
        }
    }

"""

def parse_args():
    """
    Command-line arguments to the system.
    :return: the provided parsed args bundle
    """

    parser = argparse.ArgumentParser(prog = 'get_calling_context.py', description='parse the interprocedural control flow graph of a binary')

    # ICFG Output Directory
    parser.add_argument('--icfg_dir', type=str, default='icfg', help='output location of the ICFG')
    parser.add_argument('--icfg_name', type=str, default='icfg.json', help='name of the file to write the ICFG')

    # Input Binary
    parser.add_argument('--input_binary', type=str, required=True, help='name of input binary for which to generate the ICFG')

    # Arguments for Windows Binaries
    parser.add_argument('--is_portable_executable', type=bool, default=False, help='true if the binary is a windows (Portable Executable) binary; false otherwise')
    parser.add_argument('--symbol_path', type=str, default=str(), nargs='?', const='', help='path to symbol path for input binary')

    # Ghidra Project Information
    parser.add_argument('--ghidra_project_path', type=str, required=True, help='path to Ghidra project')
    parser.add_argument('--ghidra_project_name', type=str, required=True, help='name of Ghidra project')

    args = parser.parse_args()
    return args

def generate_icfg(input_binary, project_location, project_name, symbol_path = str(), pe_binary = False):
    """
    Generates and outputs the ICFG of the provided binary in the JSON
    format described above.
    :param input_binary: the binary for which to generate the ICFG
    :param project_location: the location of the Ghidra project
    :param project_name: the name of the Ghidra project
    :param symbol_path: path to symbol path for input binary
    :param windows_binary: true if the binary is a portable executable
    """

    # Use Pyhidra to get raw connection to Ghidra, import packages
    pyhidra.start(True)
    from java.io import File
    from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.util import GhidraProgramUtilities
    from ghidra.app.script import GhidraScriptUtil
    from ghidra.program.model.listing import CodeUnitFormat
    from ghidra.program.model.listing.CodeUnitFormatOptions import ShowBlockName
    from ghidra.program.model.listing.CodeUnitFormatOptions import ShowNamespace

    icfg = {}
    with pyhidra.open_program(input_binary, project_location=project_location, project_name=project_name, analyze=False) as flat_api:
        program = flat_api.getCurrentProgram()

        # Configure symbol path for binary
        symbol_path = symbol_path.strip()
        if pe_binary and symbol_path and not symbol_path.isspace():
            symbol_path = Path(symbol_path)
            pdb_file = File(symbol_path)
            PdbUniversalAnalyzer.setPdbFileOption(program, pdb_file)

        # Analyze Program 
        if GhidraProgramUtilities.shouldAskToAnalyze(program):
            GhidraScriptUtil.acquireBundleHostReference()
            flat_api.analyzeAll(program)
            GhidraProgramUtilities.setAnalyzedFlag(program, True)
            GhidraScriptUtil.releaseBundleHostReference()

        # Set the program image base address
        imageBaseAddr = flat_api.toAddr(0)
        program.setImageBase(imageBaseAddr, 0)

        listing = program.getListing()
        monitor = ConsoleTaskMonitor()
        codeUnitFormat = CodeUnitFormat(ShowBlockName.NEVER, ShowNamespace.NON_LOCAL)

        # Generate JSON for all functions
        all_funcs = program.functionManager.getFunctions(True)
        for func in all_funcs:
            icfg[func.name] = {
                'callee': [],
                'caller': []
            }

            # Add Callers to ICFG
            callers = func.getCallingFunctions(monitor)
            for caller in callers:
                icfg[func.name]['caller'].append(caller.name)

            # Add Callees to ICFG
            instructions = listing.getInstructions(func.getEntryPoint(), True)
            for instruction in instructions:
                addr = instruction.getAddress()
                oper = instruction.getMnemonicString()

                if oper.startswith('CALL'):
                    codeUnit = listing.getCodeUnitAt(addr)
                    output = str(codeUnitFormat.getRepresentationString(codeUnit))
                    if not instruction.getRegister(0) and ("ptr" not in output or "word" not in output):
                        callee_name = output.strip().split()[1]

                        # Strip type information
                        callee_name = re.sub('<[^>]+>', '', callee_name)
                        callee_name = re.sub('_>', '', callee_name)

                        # Strip namespace
                        if '::' in callee_name:
                            idx = callee_name.rindex('::', 0, len(callee_name))
                            callee_name = '<EXTERNAL>' + callee_name[idx:]

                        icfg[func.name]['callee'].append(callee_name)

                if flat_api.getFunctionContaining(addr) != func:
                    break

    return icfg


def main():
    """
    Sets up output directory for the ICFG, generates the ICFG,
    and writes the ICFG to the output directory.
    """

    # Parse arguments
    args = parse_args()

    # Use Pyhidra to get raw connection to Ghidra, import packages
    pyhidra.start(True)

    # Create the ICFG Output Directory if it does not exist
    icfg_dir = args.icfg_dir
    if not os.path.exists(icfg_dir):
        os.makedirs(icfg_dir)

    icfg_name = args.icfg_name
    if not icfg_name.endswith('.json'):
        raise ValueError('ICFG File Name extension must be .json')

    # Generate the ICFG
    input_binary = args.input_binary
    project_location = args.ghidra_project_path
    project_name = args.ghidra_project_name
    pe_binary = args.is_portable_executable
    symbol_path = args.symbol_path
    icfg = generate_icfg(input_binary, project_location, project_name, symbol_path, pe_binary)

    # Write the ICFG
    with open(os.path.join(icfg_dir, icfg_name), 'w') as f:
        json.dump(icfg, f)
        print('[*] The interprocedural CFG is saved in: ' + icfg_dir)
        print('[*] The interprocedural CFG is saved in the file: ' + icfg_name)

if __name__ == '__main__':
    main()
