import ppdeep
import pefile
import datetime
import os
import magic

# The list contains examples of malware files
files_path = ["test_malware/1c89d6ca", "test_malware/02a69029",
              "test_malware/5c36bf95", "test_malware/7a3902ed",
              "test_malware/42b557f9", "test_malware/1884d0d7",
              "test_malware/aa85baad", "test_malware/aad0bc51",
              "test_malware/cf18f478", "test_malware/d60a4dfc",
              "test_malware/ffb6d57d"]


def is_pe_file(file_path):
    """The function checks if there are any pe files and returns only those"""
    pe_files = []
    for file in file_path:
        try:
            pe = pefile.PE(file)
            pe_files.append(file)
        except pefile.PEFormatError:
            pass
    return pe_files


def get_creation_time(file_path):
    """The function determines the date the file was created"""
    for file in file_path:
        pe = pefile.PE(file)
        timestamp = pe.FILE_HEADER.TimeDateStamp
        time_datetime = datetime.datetime.utcfromtimestamp(timestamp)
        print(f'The file: {file} was created by {time_datetime}')


def pe_resources(file_path):
    """The function determines the availability and type of resources"""
    for file in file_path:
        pe = pefile.PE(file)
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            print(f"{'-' * 10} \nResources in the {file}:")
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                print(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))


def libmagic_resources(file_path):
    """The function determines the content of resources by signature (libmagic)"""
    for file in file_path:
        print(f'File: {file} {magic.from_file(file)}')


def hashes_section(file_path):
    """The function calculates the hashes of the sections of the file"""
    pe = pefile.PE(file_path)
    section_hashes = {}
    for section in pe.sections:
        section_data = section.get_data()
        section_hash = ppdeep.hash(section_data)
        section_name = section.Name.decode().strip('\x00')
        section_hashes[section_name] = section_hash
    return section_hashes


def hashes(file_path):
    """The function compares hashes of sections between files"""
    for i in range(len(file_path)):
        for j in range(i + 1, len(file_path)):
            sections1 = hashes_section(file_path[i])
            sections2 = hashes_section(file_path[j])

            for section_name in sections1:
                if section_name in sections2:
                    similarity = ppdeep.compare(sections1[section_name], sections2[section_name])
                    print(f"{'-' * 10}   Similarity between {os.path.basename(file_path[i])}{section_name} and"
                          f" {os.path.basename(file_path[j])}{section_name}: {similarity}")
                    print(f"Hash for {os.path.basename(file_path[i])}"
                          f"{section_name}: {sections1[section_name]}")
                    print(f"Hash for {os.path.basename(file_path[j])}{section_name}: {sections2[section_name]}")


pe_files = is_pe_file(files_path)
print(pe_files)

print('Task №1 (determine the date and time of creation of the executable file)')
get_creation_time(pe_files)
print('\nTask №2 (availability and type of resources)')
pe_resources(pe_files)
print('\nTask №3 (content of resources by signature (libmagic))')
libmagic_resources(pe_files)
print('\nTask №4 (calculates and compares fuzzy hashes of PE sections in all files)')
hashes(pe_files)
