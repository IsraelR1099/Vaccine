import sys
import argparse

if __name__ == '__main__':
    default_file = "data.txt"
    print(f"default data {default_file}")
    parser = argparse.ArgumentParser(
        description="Vaccine SQL Injection",)
    parser.add_argument(
        '-o', '--output', help="Output file", default=default_file)
    parser.add_argument(
            '-X', '--request', help="HTTP request method", default="GET")
    args = parser.parse_args()
