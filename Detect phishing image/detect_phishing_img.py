import docx2txt
import os
from PIL import Image
import pytesseract


def extract_images_from_doc(document_path, output_folder):
    """The function extracts images from the document and saves them to the specified folder"""
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    text = docx2txt.process(document_path, output_folder)

    print(f"Images extracted and saved to {output_folder} from {document_path}")


def read_image_text(image_path):
    """The function reads the text from the image"""
    text = pytesseract.image_to_string(Image.open(image_path))
    return text


def check_for_macros(image_folder, document_path):
    """The function checks the image for macros"""
    for filename in os.listdir(image_folder):
        if filename.lower().endswith((".jpeg", ".jpg", ".png")):
            image_path = os.path.join(image_folder, filename)
            text = read_image_text(image_path)
            if "locked" in text.lower():
                print(f"File: {document_path} may be phishing because it has words linked by macros")


document_path = "test_malware/d0908c99"
output_image_folder = "saved images"

extract_images_from_doc(document_path, output_image_folder)
check_for_macros(output_image_folder, document_path)
