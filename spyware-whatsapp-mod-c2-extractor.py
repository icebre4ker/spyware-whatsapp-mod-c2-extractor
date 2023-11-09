#! /usr/bin/env python3

"""
Python script for extracting (statically) the C2 from spyware WhatsApp mod
For more details about spyware WhatsApp mod: https://securelist.com/spyware-whatsapp-mod/110984/

Author: @icebre4ker
License: MIT
"""

__author__ = '@icebre4ker'
__version__ = "0.1"


import re
import sys
import base64
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

GREEN = "\033[92m"
RESET = "\033[0m"  # Reset to default text color


def is_base64(string_text):
    try:
        decoded_bytes = base64.b64decode(string_text)
        return True
    except Exception:
        return False

def search_c2(possible_c2):
    url_pattern = r'(?:http|https):\/\/[\w/\-?=%.]+\.[\w/\-?=%.]+(?:\?[\w/\-?=%.]*)?(?:#[\w/\-?=%.]*)?'
    matches = re.match(url_pattern, possible_c2)
    if matches:
        print(matches.group())

def extract_strings(apk_file):
    strings_list = []
    try:
        apk = APK(apk_file)
        print(GREEN + f"[+] Parsing instructions..." + RESET)
        for dex in apk.get_all_dex():
            dvm = DalvikVMFormat(dex)
            methods = dvm.get_methods()
            for method in methods:
                method_sign = str(method)
                if "Ljava/lang/String; [access_flags=public final]" in method_sign and method.get_code():
                    bytes_values = []
                    for instruction in method.get_code().get_bc().get_instructions():
                        tmp_inst_list = instruction.get_output().split(",")
                        if tmp_inst_list[0] == "v1" and len(tmp_inst_list) == 2:
                            get_value = tmp_inst_list[1].strip()
                            if get_value.isdigit():
                                bytes_values.append(int(get_value))
                            elif get_value.split("#")[0].strip().isdigit():
                                bytes_values.append(int(get_value.split("#")[0].strip()))
                    item = "".join(chr(value % 256) for value in bytes_values)
                    strings_list.append(item)
        return strings_list
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py path/to/apk_file.apk")
        sys.exit(1)
    apk_file = sys.argv[1]
    strings_list = extract_strings(apk_file)
    print(GREEN + f"[+] Looking for c2..." + RESET)
    for s in strings_list:
        if is_base64(s):
            byte_string = base64.b64decode(s)
            elem = byte_string.decode('utf-8', errors="ignore")
        else:
            elem = s
        search_c2(elem)

if __name__ == "__main__":
    main()