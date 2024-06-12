#!/opt/privacyidea/bin/python


"""
Documentation of the Certificate Check Script

Overview:

This script is used to check TLS certificates for web servers and LDAP servers,
as well as CA certificates. It allows you to check the validity of certificates
and issue warnings if a certificate is about to expire.
The script can optionally create log files.

Usage:

The script is executed from the command line
and supports several arguments to configure the certificate checks.

Command Line Arguments:

- `--days`: (optional) Number of days before expiration to issue a warning.
            If not set, it will use 30 days as default.
- `--config-dir`: Directory to search for web server configuration files.
- `--web`: Checks the web server certificate.
- `--ldap`: Checks the LDAP server certificate and corresponding CA certificate.
- `--logging`: Path to the log file. If not set, logs will be printed to stdout.
- `--exclude`: Resolvers to exclude from the check.

Example Invocations:

1. Check all certificates and log to a file:
   "check_certificates.py"

2. Check only web server certificates and output to console:
   "check_certificates.py --web"

3. Check LDAP server certificates with a specific threshold value (days):
   "check_certificates.py --days 60 --ldap"

Example for stdout or logging:

1. "check_certificates.py --days 120 2>> /path/to/your/log.log"
or
2. "check_certificates.py --days 120 --logging /path/to/your/log.log"


Example for exclude a resolver or more resolvers:

1. "check_certificates.py --ldap --exclude resolver_name1"
2. "check_certificates.py --ldap --exclude resolver_name1 resolver_name2"

Example for a non default configuration location:

"PRIVACYIDEA_CONFIGFILE=/path/to/pi.cfg check_certificates.py"


Sample Output:

When the script runs, the output may look like this:

2024-05-22 09:54:05,621 - INFO - Web server certificate is valid for 1333 more days.

2024-05-22 09:54:07,088 - INFO - LDAP server from resolver "ad" certificate
 is valid for 123 more days.
2024-05-22 09:54:07,089 - INFO - CA issuer from resolver "ad" certificate
 is valid for 614 more days.
2024-05-22 09:54:07,092 - INFO - The LDAP server ad certificate
 is validly signed by its issuer.
2024-05-22 09:54:07,175 - INFO - LDAP server from resolver "ucs07" certificate
 is valid for 1369 more days.
2024-05-22 09:54:07,249 - INFO - LDAP server from resolver "ucs05" certificate
 is valid for 878 more days.

2024-05-17 13:39:15,315 - INFO - CA issuer from resolver "ad" certificate
 is valid for 619 more days.
2024-05-17 13:39:15,316 - INFO - CA issuer from resolver "ucs07" certificate
 is valid for 1373 more days.
2024-05-17 13:39:15,316 - INFO - CA issuer from resolver "ucs05" certificate is
 valid for 883 more days.


Summary:

This script is a helpful tool for administrators to monitor the validity
of TLS certificates in their systems and receive timely warnings when
certificates need to be renewed.
By supporting log files and various operating modes,
it can be flexibly integrated into different monitoring and maintenance processes.
"""

import argparse
import json
import subprocess
import os
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import logging
import re


def setup_logging(log_path=None):
    """
    Set up logging to file if log_path is specified, otherwise log to console.

    :param log_path: The path to the log file.
    """
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    if log_path:
        logging.basicConfig(
            filename=log_path, level=logging.INFO, format=log_format)
    else:
        logging.basicConfig(level=logging.INFO, format=log_format)


def log_message(message, error=False, warning=False):
    """
    Log a message to both the console and a log file.

    :param message: The message to log.
    :param error: If True, log the message as an error.
    :param warning: If True, log the message as a warning.
    """
    if error:
        logging.error(message)
    elif warning:
        logging.warning(message)
    else:
        logging.info(message)


def find_config_files(directory, file_patterns):
    """
    Find configuration files in a directory that match specified patterns.

    :param directory: The directory to search in.
    :param file_patterns: A list of file patterns to match.
    :return: A generator yielding paths to the matching files.
    """
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.endswith(pattern) 
                for pattern in file_patterns) or not os.path.splitext(file)[1]:
                yield os.path.join(root, file)


def extract_nginx_certificate_paths(config_path):
    """
    Extract the certificate paths from an Nginx configuration file.

    :param config_path: The path to the configuration file.
    :return: A list of extracted certificate paths.
    """
    cert_paths = []
    try:
        with open(config_path, 'r') as file:
            content = file.read()
            cert_matches = re.findall(r'ssl_certificate\s+(\S+);', content)
            cert_paths.extend(cert_matches)
    except Exception as e:
        log_message(f"Error reading {config_path}: {e}", error=True)
    return cert_paths


def extract_apache_certificate_path(config_path):
    """
    Extract the certificate path from an Apache configuration file.

    :param config_path: The path to the configuration file.
    :return: The extracted certificate path, or None if not found.
    """
    cert_path = None
    try:
        with open(config_path, 'r') as file:
            for line in file:
                if 'SSLCertificateFile' in line and not line.strip().startswith('#'):
                    cert_path = line.split()[-1].strip()
                    break
    except Exception as e:
        log_message(f"Error reading {config_path}: {e}", error=True)
    return cert_path


def load_certificates(cert_path, ca_path=None):
    """
    Load certificates from specified paths.

    :param cert_path: The path to the certificate file.
    :param ca_path: The path to the CA certificate file (optional).
    :return: A tuple of (certificate, CA certificate).
    """
    try:
        cert = None
        if cert_path:
            with open(cert_path, 'rb') as file:
                cert = x509.load_pem_x509_certificate(file.read(), default_backend())

        ca_cert = None
        if ca_path:
            with open(ca_path, 'rb') as file:
                ca_cert = x509.load_pem_x509_certificate(file.read(), default_backend())

        return cert, ca_cert
    except Exception as e:
        log_message(
            f"Failed to load certificates from {cert_path} or {ca_path}: {e}", error=True)
        return None, None


def check_certificate_expiry(cert, days, cert_description):
    """
    Check if a certificate will expire within a specified number of days.

    :param cert: The certificate to check.
    :param days: The number of days to check for expiry.
    :param cert_description: A description of the certificate.
    """
    if cert:
        try:
            days_to_expire = (cert.not_valid_after_utc - datetime.now(tz=timezone.utc)).days
        except AttributeError:
            # looks like pyca/cryptography version < 42.0
            not_valid_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
            days_to_expire = (not_valid_after - datetime.now(tz=timezone.utc)).days
        message = f'{cert_description} certificate is valid for {days_to_expire} more days.'
        log_message(message)
        if days_to_expire <= days:
            log_message(
                f"Warning: The {cert_description} "
                f"certificate will expire in {days_to_expire} days or less. "
                f"Please renew it timely.",
                warning=True)


def get_certificate_from_server(server_address, port, starttls=False):
    """
    Retrieve the server certificate using openssl.

    :param server_address: The address of the server.
    :param port: The port to connect to.
    :param starttls: Whether to use STARTTLS for LDAP connections.
    :return: The server certificate, or None if not found.
    """
    try:
        if starttls:
            cmd = (
                f"echo | openssl s_client -connect {server_address}:{port} -starttls ldap "
                "2>/dev/null | openssl x509")
        else:
            cmd = (f"echo | openssl s_client -connect {server_address}:{port} "
                   f"2>/dev/null | openssl x509")
        cert_pem = subprocess.check_output(cmd, shell=True)
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        return cert
    except subprocess.CalledProcessError:
        log_message(
            f"Failed to retrieve certificate from {server_address}:{port}."
            f" Trying connection check...",
            warning=True)
        try:
            cmd = f"echo | openssl s_client -connect {server_address}:{port} 2>/dev/null"
            connection_output = subprocess.check_output(cmd, shell=True).decode('utf-8')
            if "CONNECTED(00000003)" in connection_output:
                log_message(
                    f"Connection to {server_address}:{port} successful, but no certificate found.",
                    warning=True)
                return None
            else:
                log_message(f"Failed to establish connection to "
                            f"{server_address}:{port}.", error=True)
                return None
        except subprocess.CalledProcessError as ce:
            log_message(f"Failed to connect to {server_address}:{port}: {ce}", error=True)
            return None


def verify_certificate_signature(client_cert, ca_cert, cert_description):
    """
    Verify if the client certificate is signed by the CA certificate.

    :param client_cert: The client certificate to verify.
    :param ca_cert: The CA certificate to use for verification.
    :param cert_description: A description of the certificate.
    """
    try:
        ca_cert.public_key().verify(
            client_cert.signature,
            client_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            client_cert.signature_hash_algorithm)
        log_message(f"The {cert_description} certificate is validly signed by its issuer.")
    except Exception as e:
        log_message(
            f"Verification failed: The {cert_description} "
            f"certificate is not properly signed by its issuer: "
            f"{e}",
            error=True)


def main():
    """
    Main function to check TLS certificates and issue warnings if they are about to expire.
    """
    parser = argparse.ArgumentParser(
        description='Check certificates and issue a warning if expiration is imminent.')
    parser.add_argument(
        '--days', type=int, default=30, help='No. of days before expiration to issue a warning.')
    parser.add_argument(
        '--config-dir', type=str, help='Directory to search for web server config files.')
    parser.add_argument(
        '--web', action='store_true', help='Check the web server certificate.')
    parser.add_argument(
        '--ldap', action='store_true', help='Check the LDAP server certificate.')
    parser.add_argument(
        '--logging', type=str, help='If log-path not set, logs will be printed to stdout.')
    parser.add_argument(
        '--exclude', type=str, nargs='*', help='Resolvers to exclude from the check.')
    args = parser.parse_args()

    # Setup logging based on the provided argument
    setup_logging(args.logging)

    # Convert exclude list to set for faster lookup
    exclude_resolvers = set(args.exclude) if args.exclude else set()

    # Determine what to check
    check_web = args.web or not args.ldap
    check_ldap = args.ldap or not args.web

    # Web server certificates check
    if check_web:
        file_patterns = ['.conf']
        config_dirs = {
            "apache": "/etc/apache2/sites-enabled",
            "httpd": "/etc/httpd/conf.d",
            "nginx": "/etc/nginx/sites-enabled"}
        if args.config_dir:
            config_dirs = {"custom": args.config_dir}

        for name, directory in config_dirs.items():
            config_paths = list(find_config_files(directory, file_patterns))
            for path in config_paths:
                if name == "nginx":
                    cert_paths = extract_nginx_certificate_paths(path)
                else:
                    cert_paths = [extract_apache_certificate_path(path)]
                for cert_path in cert_paths:
                    if cert_path:
                        cert, _ = load_certificates(cert_path)
                        check_certificate_expiry(cert, args.days, 'Web server')

    # LDAP server certificates check
    if check_ldap:
        try:
            cmd = "pi-manage config exporter -t resolver -f json"
            data = subprocess.check_output(cmd, shell=True).decode('utf-8')
            data = json.loads(data)
            for resolver_name, resolver_data in data["resolver"].items():
                if resolver_name in exclude_resolvers:
                    log_message(f"Skipping excluded resolver: {resolver_name}")
                    continue
                ldap_uri = resolver_data["data"].get("LDAPURI")
                if ldap_uri:
                    uri_parts = ldap_uri.split("://")
                    if len(uri_parts) == 2:
                        scheme, server_info = uri_parts
                        server_info = server_info.split(":")
                        server_address = server_info[0]
                        port = server_info[1] if len(server_info) == 2 \
                            else (636 if scheme == "ldaps" else 389)
                        starttls = scheme == "ldap"
                        cert = get_certificate_from_server(server_address, port, starttls)
                        if cert:
                            check_certificate_expiry(
                                cert, args.days, f'LDAP server from resolver "{resolver_name}"')
                        else:
                            log_message(
                                f"No certificate found for LDAP server from resolver "
                                f"\"{resolver_name}\" at "
                                f"{server_address}:{port}", warning=True)
                        if resolver_data["data"].get("TLS_VERIFY", "").lower() == "true":
                            ca_path = resolver_data["data"].get("TLS_CA_FILE")
                            if ca_path:
                                _, ca_cert = load_certificates(cert_path=None, ca_path=ca_path)
                                if ca_cert:
                                    check_certificate_expiry(
                                        ca_cert, args.days, f'CA issuer from resolver'
                                                            f' "{resolver_name}"')
                                    if cert and ca_cert:
                                        verify_certificate_signature(
                                            cert, ca_cert, f'LDAP server {resolver_name}')
        except subprocess.CalledProcessError as e:
            log_message(f"Failed to execute command: {e}", error=True)
        except json.JSONDecodeError:
            log_message("Failed to parse JSON from output.", error=True)
        except Exception as e:
            log_message(f"An unexpected error occurred: {e}", error=True)


if __name__ == "__main__":
    main()

