import ssl
import socket
import datetime

def get_ssl_certificate_info(hostname, port=443):
    """Retrieves SSL certificate information for a given host and returns it as a dictionary."""
    result = {
        "hostname": hostname,
        "port": port,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "status": None,
        "error": None
    }
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["subject"] = cert.get("subject")
                result["issuer"] = cert.get("issuer")

                not_before_str = cert.get("notBefore")
                not_after_str = cert.get("notAfter")
                result["not_before"] = not_before_str
                result["not_after"] = not_after_str

                # Try to parse the certificate dates
                not_before = None
                not_after = None
                try:
                    not_before = datetime.datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
                except (ValueError, TypeError):
                    # Could not parse dates, leave as strings
                    result["status"] = "Date validity check limited due to parsing issue."

                if not_before and not_after:
                    now = datetime.datetime.now()
                    result["not_before"] = not_before
                    result["not_after"] = not_after
                    if now < not_before:
                        result["status"] = "Certificate is not yet valid."
                    elif now > not_after:
                        result["status"] = "Certificate has expired."
                    else:
                        result["status"] = "Certificate is currently valid."
    except (socket.error, ssl.SSLError, ConnectionRefusedError, ssl.CertificateError) as e:
        result["error"] = f"Error retrieving SSL certificate for {hostname}: {e}"
    return result




