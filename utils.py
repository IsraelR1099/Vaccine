def vulnerable(response):
    if response is None:
        return False
    error_msgs = [
        "SQL syntax",
        "Warning",
        "mysql_",
        "ORA-",
        # MySql
        "You have an error in your SQL syntax",
        # Microsoft SQL server
        "Unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
        "Fatal error",
        "unterminated string constant",
        # PostgreSQL
        "syntax error at or near",
        "unterminated quoted string at or near"
        ]
    for msg in error_msgs:
        if msg.lower() in response.content.decode().lower():
            return True
    return False


def write_to_file(filename, content):
    try:
        with open(filename, "a") as file:
            file.write(content + "\n")
    except OSError as e:
        print({f"[-] Error writing on file: {filename}"})


def check_response(response):
    """
    Check data from the response to check for vulnerabilities
    """
    error_msgs = [
        "You have an error in your SQL syntax",
        "Warning: mysql_fetch_array()",
        "Warning: mysql_fetch_assoc()",
        "The used SELECT statements have a different number of columns",
        "Unknown column",
        "SQL syntax",
        "each UNION query must have the same number of columns"
        ]
    response_text = response.content.decode().lower()
    print(f"response text: {response_text}")
    for error_msg in error_msgs:
        if error_msg.lower() in response_text:
            return False

    return True
