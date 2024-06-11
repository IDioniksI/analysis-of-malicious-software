import hashlib
import magic
from PIL import Image
from olefile import OleFileIO
from oletools.oleid import OleID

file_paths = ["test_malware/1c89d6ca", "test_malware/02a69029",
              "test_malware/5c36bf95", "test_malware/7a3902ed",
              "test_malware/42b557f9", "test_malware/1884d0d7",
              "test_malware/aa85baad", "test_malware/aad0bc51",
              "test_malware/cf18f478", "test_malware/d60a4dfc",
              "test_malware/ffb6d57d"]


def calculate_sha256(data):
    """The function calculates a hash for files that fall into it"""
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def analyze_ole2_document(file_path):
    """A function that directly analyzes the file and outputs various information"""
    try:
        with open(file_path, 'rb') as file:
            data = file.read()

        sha256_hash = calculate_sha256(data)
        print(f"{'-' * 40} \nFile: {file_path}")
        print(f"SHA-256: {sha256_hash}")

        ole_id = OleID(file_path)
        indicators = ole_id.check()
        for indicator in indicators:
            print(f"{indicator.name}: {indicator.value}")
            print(f"Type: {indicator.type}")
            print(f"Description: {indicator.description}")
            print()

        ole_file = OleFileIO(file_path)
        for stream_name in ole_file.listdir():
            stream_data = ole_file.openstream(stream_name[0])

            if stream_name[0].lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                try:
                    m = magic.Magic()
                    mime_type = m.from_buffer(stream_data.getvalue())
                    if 'image' in mime_type:
                        image = Image(stream_data)
                        print("Image Metadata:")
                        for key, value in image.get_all().items():
                            print(f"{key}: {value}")
                except Exception as e:
                    print(f"Error processing image: {e}")

            hash_stream = calculate_sha256(stream_data.getvalue())
            print(f'Hash for {stream_name[0]} is {hash_stream}')
    except:
        pass


for file_path in file_paths:
    analyze_ole2_document(file_path)
