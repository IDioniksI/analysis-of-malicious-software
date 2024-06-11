## Analysis PE files
[Static analysis of PE](static_analysis_of_PE.py): The script analyzes PE/PE+ executable files by list and determines:
- Date and time of creation of the executable file according to the header data (TimeDateStamp);
- Availability and type of resources (PE resources);
- Resource content by signature (libmagic);
- Calculates and compares fuzzy hashes of PE sections in all files.

[Bypassing PEiD signatures](bypassing_PEiD_signatures.py): A script that modifies the executable to bypass PEiD 
signatures bound to the entry point (ep_only=true)
<br>In the code segment, find an unused area (code cave: alignment of 0 at the end of the segment, sequences of 
0xCC/int3 of sufficient size, etc.), set the entry point (PE EntryPoint) to it, write the control transfer code to the 
original entry point

[Static analysis of Microsoft Office documents](static_analysis_of_MS_Office.py): A script that parses Microsoft Office 
documents in OLE2 format by list, calculates SHA-256 for OLE streams, if the stream is an image - outputs EXIF metadata