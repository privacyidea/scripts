#!/opt/privacyidea/bin/python

import argparse
import json
import subprocess
import os
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import logging


def setup_logging(log_path=None):
    """
    Set up logging to file if log_path is specified, otherwise log to console.
    :param log_path: The path to the log file.
    """
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    if log_path:
        logging.basicConfig(filename=log_path, level=logging.INFO, format=log_format)
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
    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.endswith(pattern) for pattern in file_patterns):
                yield os.path.join(root, file)


def extract_certificate_path(config_path):
    """
    Extract the certificate path from a configuration file.
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
        log_message(f"Error reading {config_path}: {str(e)}", error=True)
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
        log_message(f"Failed to load certificates from "
                    f"{cert_path} or {ca_path}: {str(e)}", error=True)
        return None, None


def check_certificate_expiry(cert, days, cert_description):
    """
    Check if a certificate will expire within a specified number of days.
    :param cert: The certificate to check.
    :param days: The number of days to check for expiry.
    :param cert_description: A description of the certificate.
    """
    if cert:
        days_to_expire = (cert.not_valid_after - datetime.now()).days
        message = f'{cert_description} certificate is valid for {days_to_expire} more days.'
        log_message(message)
        if days_to_expire <= days:
            log_message(f"Warning: The {cert_description} certificate will expire in "
                        f"{days_to_expire} days or less. Please renew it timely.", warning=True)


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
            cmd = (f"echo | openssl s_client -connect {server_address}:{port} "
                   f"-starttls ldap 2>/dev/null | openssl x509")
        else:
            cmd = (f"echo | openssl s_client -connect {server_address}:{port} "
                   f"2>/dev/null | openssl x509")
        cert_pem = subprocess.check_output(cmd, shell=True)
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        return cert
    except subprocess.CalledProcessError as e:
        # If failed to retrieve certificate, try checking connection
        log_message(f"Failed to retrieve certificate from {server_address}:{port}. "
                    f"Trying connection check...", warning=True)
        try:
            cmd = f"echo | openssl s_client -connect {server_address}:{port} 2>/dev/null"
            connection_output = subprocess.check_output(cmd, shell=True).decode('utf-8')
            if "CONNECTED(00000003)" in connection_output:
                log_message(f"Connection to {server_address}:{port} successful, "
                            f"but no certificate found.", warning=True)
                return None
            else:
                log_message(f"Failed to establish connection to "
                            f"{server_address}:{port}.", error=True)
                return None
        except subprocess.CalledProcessError as ce:
            log_message(f"Failed to connect to {server_address}:{port}: {str(ce)}", error=True)
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
        log_message(f"Verification failed: The {cert_description} certificate "
                    f"is not properly signed by its issuer: {str(e)}", error=True)


def main():
    """
    Main function to check TLS certificates and issue warnings if they are about to expire.
    """
    parser = argparse.ArgumentParser(description='Check TLS certificates and issue a warning '
                                                 'if expiration is imminent.')
    parser.add_argument('--days', type=int, required=True, help='Number of days before expiration '
                                                                'to issue a warning.')
    parser.add_argument('--config-dir', type=str, help='Directory to search '
                                                       'for web server config files.')
    parser.add_argument('--web', action='store_true', help='Check the web server certificate.')
    parser.add_argument('--ldap', action='store_true', help='Check the LDAP server certificate.')
    parser.add_argument('--ca', action='store_true', help='Check the CA issuer certificate.')
    parser.add_argument('--all', action='store_true', help='Check all web, LDAP, '
                                                           'and CA issuer certificates.')
    parser.add_argument('--logging', type=str, help='Path to the log file. '
                                                    'If not set, logs will be printed to stdout.')
    args = parser.parse_args()

    # Setup logging based on the provided argument
    setup_logging(args.logging)

    # Enable CA checks if --all is specified
    ca_checks = args.ca

    # Web server certificates check
    if args.web or args.all:
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
                cert_path = extract_certificate_path(path)
                if cert_path:
                    cert, _ = load_certificates(cert_path)
                    check_certificate_expiry(cert, args.days, 'Web server')

    # LDAP server certificates check
    if args.ldap or args.all:
        try:
            cmd = "pi-manage config exporter -t resolver -f json"
            data = subprocess.check_output(cmd, shell=True).decode('utf-8')
            data = json.loads(data)
            for resolver_name, resolver_data in data["resolver"].items():
                ldap_uri = resolver_data["data"].get("LDAPURI")
                if ldap_uri:
                    uri_parts = ldap_uri.split("://")
                    if len(uri_parts) == 2:
                        scheme, server_info = uri_parts
                        server_info = server_info.split(":")
                        server_address = server_info[0]
                        port = server_info[1] if (len(server_info) ==
                                                  2) else (636 if scheme == "ldaps" else 389)
                        starttls = scheme == "ldap"
                        cert = get_certificate_from_server(server_address, port, starttls)
                        if cert:
                            check_certificate_expiry(cert, args.days, f'LDAP server '
                                                                      f'from resolver "{resolver_name}"')
                        else:
                            log_message(f"No certificate found for LDAP server "
                                        f"from resolver \"{resolver_name}\" "
                                        f"at {server_address}:{port}", warning=True)
                        # Check CA certificate if TLS_VERIFY is set
                        if resolver_data["data"].get("TLS_VERIFY", "").lower() == "true":
                            ca_path = resolver_data["data"].get("TLS_CA_FILE")
                            if ca_path:
                                _, ca_cert = load_certificates(cert_path=None, ca_path=ca_path)
                                if ca_cert:
                                    check_certificate_expiry(ca_cert, args.days,
                                                             f'CA issuer from resolver "{resolver_name}"')
                                    if cert and ca_cert:
                                        verify_certificate_signature(cert, ca_cert,
                                                                     f'LDAP server {resolver_name}')
        except subprocess.CalledProcessError as e:
            log_message(f"Failed to execute command: {str(e)}", error=True)
        except json.JSONDecodeError:
            log_message("Failed to parse JSON from output.", error=True)
        except Exception as e:
            log_message(f"An unexpected error occurred: {str(e)}", error=True)

    # CA issuer certificates check
    if ca_checks:
        try:
            cmd = "pi-manage config exporter -t resolver -f json"
            data = subprocess.check_output(cmd, shell=True).decode('utf-8')
            data = json.loads(data)
            for resolver_name, resolver_data in data["resolver"].items():
                if resolver_data["data"].get("TLS_VERIFY", "").lower() == "true":
                    ca_path = resolver_data["data"].get("TLS_CA_FILE")
                    if ca_path:
                        _, ca_cert = load_certificates(cert_path=None, ca_path=ca_path)
                        if ca_cert:
                            check_certificate_expiry(ca_cert, args.days,
                                                     f'CA issuer from resolver "{resolver_name}"')
        except subprocess.CalledProcessError as e:
            log_message(f"Failed to execute command: {str(e)}", error=True)
        except json.JSONDecodeError:
            log_message("Failed to parse JSON from output.", error=True)
        except Exception as e:
            log_message(f"An unexpected error occurred: {str(e)}", error=True)


if __name__ == "__main__":
    main()


