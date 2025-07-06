import sys
import json
from dfd_parser.xml_parser import extract_from_xml

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("❌ Usage: python3 fraitmo.py <path_to_file.xml>")
        sys.exit(1)

    xml_path = sys.argv[1]
    try:
        parsed = extract_from_xml(xml_path)
        print(json.dumps(parsed, indent=2))
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)