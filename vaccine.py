import sys
import argparse
import requests

def make_request(file, http_method, url):
    print(f"Output file: {output_file}")
    print(f"HTTP method: {http_method}")
    print(f"Target URL: {target_url}")
    try:
        if http_method == "GET":
            response = requests.get(url)
            response.raise_for_status()
        elif http_method == "POST":
            response = requests.post(url)
            response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error: Invalid URL: '{url}': {e}")
        sys.exit(1)
    html_response = response.text
    print(html_response)


if __name__ == '__main__':
    default_file = "data.txt"
    if len(sys.argv) < 2:
        print("Please provide a valid input.")
        print("./vaccine [-oX] URL")
        print(" -o: Archive file.")
        print(" -X: Type of request.")
        sys.exit(1)
    parser = argparse.ArgumentParser(
        description="Vaccine SQL Injection",)
    parser.add_argument(
        '-o', '--output', help="Output file", default=default_file)
    parser.add_argument(
            '-X', '--request', help="HTTP request method", default="GET")
    parser.add_argument(
        'url', help="Target URL for SQL Injection")
    args = parser.parse_args()
    output_file = args.output
    request_method = args.request
    target_url = args.url
    make_request(output_file, request_method, target_url)
