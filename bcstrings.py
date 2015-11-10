#!/usr/bin/env python3
##############################################################
# Dump strings that are encoded as bytecode instructions
# Nov. 2015
##############################################################
import sys
import pefile
import string
from capstone import *  # Capstone disassembler

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Insufficient arguments (usage: bcstrings <file_path>)')
        sys.exit(1)
    in_file = sys.argv[1]
    try:
        f = open(in_file, 'rb')
        file_data = f.read()
        f.close()
        pe = pefile.PE(data=file_data, fast_load=True)
        md = Cs(CS_ARCH_X86, CS_MODE_32)  # Could detect from the header...
        md.detail = True
        md.skipdata = False
        offset = int(pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        str_accum = ''
        for dsm in md.disasm(file_data[offset:], pe.OPTIONAL_HEADER.ImageBase):
            #Example: mov byte ptr [ebp - 0xb5], 0x64
            if dsm.mnemonic == 'mov' and dsm.op_count(CS_OP_MEM) == 1 and dsm.op_count(CS_OP_IMM) == 1:
                size = dsm.op_str.split()[0]
                val = dsm.op_find(CS_OP_IMM,1).imm
                #Null still terminates
                if val == 0 and len(str_accum) > 0:
                    print(str_accum)
                    str_accum = ''
                #Non-null and valid ASCII gets appended
                elif 0 < val <= 255:
                    if chr(val) in string.printable:
                        str_accum += chr(val)
    except:
        raise

    sys.exit(0)