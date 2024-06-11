import lief
import keystone

pe_file_path = 'test_malware/d60a4dfc'


def load_pe_file(file_path):
    """The function parses (analyzes) the structure of the pe-file"""
    pe_file = lief.parse(file_path)
    return pe_file


def original_entrypoint(pe_file):
    """The function determines the initial entry point and outputs it to the terminal as hex"""
    entrypoint = pe_file.optional_header.addressof_entrypoint
    print(f'Original entrypoint: {hex(entrypoint)}')
    return entrypoint


def assemble_jmp_code(entrypoint):
    """The function reproduces the assembly code, and goes to the entrypoint"""
    CODE = f'JMP {entrypoint};'.encode()
    ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
    encoding, _ = ks.asm(CODE)
    encoded = bytes(encoding)
    return encoded


def find_code_cave(pe_file, encoded):
    """The function looks for a place where all bytes = 0 to interact with it further"""
    text_section = pe_file.get_section('.text')
    text = bytes(text_section.content)
    code_cave = text.find(b"\x00" * len(encoded))
    return code_cave


def new_entrypoint(entrypoint, code_cave):
    """The function calculates a new entry point pointing to the code cave"""
    new_entrypoint = entrypoint + code_cave
    print(f'New entrypoint: {hex(new_entrypoint)}')
    return new_entrypoint


def write_pe_file(pe_file, new_entrypoint, encoded):
    """The function modifies the entrypoint and creates a new file with it"""
    pe_file.optional_header.addressof_entrypoint = new_entrypoint
    builder = lief.PE.Builder(pe_file)
    builder.build_imports(True)
    builder.build()
    builder.write('mod_file')

    with open('mod_file', 'rb+') as file:
        file.seek(new_entrypoint)
        file.write(encoded)


pe_file = load_pe_file(pe_file_path)
entrypoint = original_entrypoint(pe_file)
encoded = assemble_jmp_code(entrypoint)
code_cave = find_code_cave(pe_file, encoded)
new_entrypoint = new_entrypoint(entrypoint, code_cave)
write_pe_file(pe_file, new_entrypoint, encoded)
