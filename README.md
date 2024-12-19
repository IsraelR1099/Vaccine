# Vaccine Program

The Vaccine program is a Python tool designed to simulate SQL injection attacks. It supports a variety of injection techniques such as error-based, union-based, time-based, and boolean-based attacks. This functionality is similar to that of SQLMap, providing a versatile testing tool for vulnerabilities in web applications.

## Features

- Supports multiple SQL injection techniques:
  - **Error-based**
  - **Union-based**
  - **Time-based**
  - **Boolean-based**
- Customizable HTTP methods and output options.
- Database targeting for precision testing.

## Prerequisites

- Python 3.6 or later installed.
- Required Python libraries:
  - Requests
  - Any other dependencies should be installed using the `requirements.txt` file (if available).

## Installation

Clone the repository and navigate to the project directory:

```bash
$ git clone <repository-url>
$ cd vaccine
```

If a `requirements.txt` file is provided, install the dependencies:

```bash
$ pip install -r requirements.txt
```

## Usage

Run the program with the following syntax:

```bash
python vaccine.py [-h] [-o OUTPUT] [-X METHOD] [-d DATABASE] url
```

### Arguments

- `url` (required): The target URL to test for SQL injection vulnerabilities.

### Optional Arguments

- `-h, --help`: Show the help message and exit.
- `-o OUTPUT, --output OUTPUT`: Specify the output file to save results.
- `-X METHOD, --method METHOD`: Specify the HTTP method to use (default: `GET`).
- `-d DATABASE, --database DATABASE`: Specify the database type to target (e.g., PostgreSQL, MySQL).

### Example Commands

1. Perform SQL injection on a target URL using default options:

   ```bash
   python3 vaccine.py http://example.com/vulnerable-page
   ```

2. Save results to a file:

   ```bash
   python3 vaccine.py -o output.txt http://example.com/vulnerable-page
   ```

3. Use `POST` as the HTTP method:

   ```bash
   python3 vaccine.py -X POST http://example.com/vulnerable-page
   ```

4. Target a specific database type:

   ```bash
   python3 vaccine.py -d PostgreSQL http://example.com/vulnerable-page
   ```

## Disclaimer

This program is intended for educational purposes and security testing in authorized environments only. Unauthorized use of this tool against systems you do not own or have explicit permission to test is strictly prohibited and may be illegal.
