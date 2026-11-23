import socket
import ssl
import requests
import dns.resolver
import ipaddress
import whois
import re

from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime


# ==========================================
# PROGRESS REPORTING
# ==========================================

def update_progress(callback, stage, percent):
    """
    Send real scan progress to the Flask application.

    Callback format:
        callback(stage, percent)
    """

    if callback is None:
        return

    try:
        callback(stage, percent)
    except Exception:
        # A progress reporting error must not stop the scan.
        pass


# ==========================================
# RESULT HELPER
# ==========================================

def add_result(results, name, status, details):
    results.append({
        "name": name,
        "status": status,
        "details": str(details)
    })


def clean(value):
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value)

    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")

    if value:
        return str(value)

    return "Not publicly available"


# ==========================================
# WHOIS ANALYSIS
# ==========================================

def whois_analysis(hostname, results):
    try:
        data = whois.whois(hostname)

        add_result(results, "WHOIS Registrar", "INFO", clean(data.registrar))
        add_result(results, "WHOIS Organization", "INFO", clean(data.org))
        add_result(results, "WHOIS Creation Date", "INFO", clean(data.creation_date))
        add_result(results, "WHOIS Expiry Date", "INFO", clean(data.expiration_date))
        add_result(results, "WHOIS Name Servers", "INFO", clean(data.name_servers))

    except Exception:
        add_result(results, "WHOIS Lookup", "INFO", "WHOIS lookup unavailable")


# ==========================================
# TECHNOLOGY DETECTION
# ==========================================

def technology_detection(response, soup, results):
    """Identify technologies using publicly visible headers and HTML."""

    headers = response.headers
    page_html = response.text.lower()
    resources = []

    for tag in soup.find_all(["script", "link"]):
        resource = tag.get("src") or tag.get("href")
        if resource:
            resources.append(resource.lower())

    resource_text = " ".join(resources)
    detected = {}

    def identify(name, evidence):
        detected[name] = evidence

    server = headers.get("Server", "").lower()

    if "nginx" in server:
        identify("Nginx", "Detected in the HTTP Server header")

    if "apache" in server:
        identify("Apache", "Detected in the HTTP Server header")

    if (
        "cloudflare" in server
        or "cf-ray" in headers
        or "cf-cache-status" in headers
    ):
        identify("Cloudflare", "Cloudflare HTTP headers detected")

    powered_by = headers.get("X-Powered-By", "").lower()

    if "php" in powered_by:
        identify("PHP", "Detected in X-Powered-By header")
    elif re.search(r"""(?:src|href)=["'][^"']+\.php(?:[?#]["']|["'])""", page_html):
        identify("PHP", "Public HTML contains PHP resource references")

    generator = soup.find(
        "meta",
        attrs={"name": re.compile("^generator$", re.I)}
    )

    generator_content = (
        generator.get("content", "").lower() if generator else ""
    )

    if (
        "wordpress" in generator_content
        or "wp-content" in page_html
        or "wp-includes" in page_html
    ):
        identify("WordPress", "WordPress generator or resource paths detected")

    if "drupal" in generator_content or "/sites/default/" in page_html:
        identify("Drupal", "Drupal generator or resource paths detected")

    if "joomla" in generator_content or "/media/system/js/" in page_html:
        identify("Joomla", "Joomla generator or resource paths detected")

    if (
        "data-reactroot" in page_html
        or "react-dom" in resource_text
        or "react.production" in resource_text
        or "__next" in page_html
    ):
        identify("React", "React-related HTML or resources detected")

    if "jquery" in resource_text or "jquery.min.js" in page_html:
        identify("jQuery", "jQuery resource detected")

    if "bootstrap" in resource_text or "bootstrap.min.css" in page_html:
        identify("Bootstrap", "Bootstrap stylesheet or resource detected")

    if detected:
        for technology, evidence in sorted(detected.items()):
            add_result(results, f"Technology: {technology}", "INFO", evidence)
    else:
        add_result(
            results,
            "Technology Detection",
            "INFO",
            "No common technologies identified from public information"
        )


# ==========================================
# SECURITY SCORE CALCULATION
# ==========================================

def calculate_security_score(results):
    """
    Calculate a configuration score out of 100.

    SSL: 40 points
    HTTP security headers: 40 points
    Cookie settings: 20 points

    This is a limited configuration score, not a full security audit.
    """

    ssl_result = next(
        (r for r in results if r["name"] == "SSL Certificate"),
        None
    )

    ssl_score = (
        40 if ssl_result and ssl_result["status"] == "PASS" else 0
    )

    header_weights = {
        "Strict-Transport-Security": 10,
        "Content-Security-Policy": 10,
        "X-Frame-Options": 7,
        "X-Content-Type-Options": 7,
        "Referrer-Policy": 6
    }

    header_score = 0
    missing_headers = []

    for header, weight in header_weights.items():
        header_result = next(
            (r for r in results if r["name"] == header),
            None
        )

        if header_result and header_result["status"] == "PASS":
            header_score += weight
        else:
            missing_headers.append(header)

    cookie_results = [
        r for r in results if r["name"].startswith("Cookie: ")
    ]

    cookie_score = 20
    cookie_issues = []

    if cookie_results:
        passed_flags = 0
        total_flags = len(cookie_results) * 3

        for cookie in cookie_results:
            details = cookie["details"].lower()

            secure_match = re.search(r"secure:\s*(true|yes)", details)
            httponly_match = re.search(
                r"httponly:\s*(true|yes)", details, re.I
            )
            samesite_match = re.search(
                r"samesite:\s*([^;]+)", details, re.I
            )

            secure_ok = bool(secure_match)
            httponly_ok = bool(httponly_match)

            samesite_value = (
                samesite_match.group(1).strip().lower()
                if samesite_match else "not set"
            )

            samesite_ok = samesite_value in ("lax", "strict", "none")

            passed_flags += int(secure_ok)
            passed_flags += int(httponly_ok)
            passed_flags += int(samesite_ok)

            cookie_name = cookie["name"].replace("Cookie: ", "")

            if not secure_ok:
                cookie_issues.append(
                    f"Set the Secure flag on cookie {cookie_name}."
                )

            if not httponly_ok:
                cookie_issues.append(
                    f"Set the HttpOnly flag on cookie {cookie_name}."
                )

            if not samesite_ok:
                cookie_issues.append(
                    f"Configure an appropriate SameSite value for cookie {cookie_name}."
                )

        cookie_score = round(20 * passed_flags / total_flags)

    total_score = ssl_score + header_score + cookie_score

    if total_score >= 90:
        grade = "A"
        grade_label = "Excellent configuration"
    elif total_score >= 80:
        grade = "B"
        grade_label = "Good configuration"
    elif total_score >= 70:
        grade = "C"
        grade_label = "Fair configuration"
    elif total_score >= 60:
        grade = "D"
        grade_label = "Needs improvement"
    else:
        grade = "F"
        grade_label = "Poor configuration"

    recommendations = []

    if ssl_score == 0:
        recommendations.append(
            "Use HTTPS and install a valid TLS certificate. "
            "The certificate check did not pass."
        )

    for header in missing_headers:
        recommendations.append(
            f"Review whether your website should configure the {header} header."
        )

    recommendations.extend(cookie_issues)

    if not cookie_results:
        recommendations.append(
            "No cookies were observed in this response. "
            "Cookie security could not be meaningfully tested."
        )

    categories = {
        "SSL Certificate": {
            "score": ssl_score,
            "max": 40,
            "percent": round(ssl_score / 40 * 100)
        },
        "HTTP Security Headers": {
            "score": header_score,
            "max": 40,
            "percent": round(header_score / 40 * 100)
        },
        "Cookie Security": {
            "score": cookie_score,
            "max": 20,
            "percent": round(cookie_score / 20 * 100)
        }
    }

    return {
        "overall": total_score,
        "grade": grade,
        "grade_label": grade_label,
        "categories": categories,
        "recommendations": recommendations,
        "missing_headers": missing_headers
    }


# ==========================================
# MAIN WEBSITE SCANNER
# ==========================================

def scan_website(target, progress_callback=None):

    results = []

    def progress(stage, percent):
        update_progress(progress_callback, stage, percent)

    progress("Initializing website scan", 2)

    target = target.strip()

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urlparse(target)
    hostname = parsed.hostname

    progress("Validating target address", 5)

    if not hostname:
        add_result(
            results,
            "URL Validation",
            "FAIL",
            "Invalid website address"
        )
        progress("Scan stopped: invalid website address", 100)
        return results

    if parsed.username or parsed.password:
        add_result(
            results,
            "URL Validation",
            "FAIL",
            "URLs containing credentials are not allowed"
        )
        progress("Scan stopped: credentials in URL are not allowed", 100)
        return results

    if parsed.scheme not in ("http", "https"):
        add_result(
            results,
            "URL Validation",
            "FAIL",
            "Only HTTP and HTTPS websites are supported"
        )
        progress("Scan stopped: unsupported URL scheme", 100)
        return results

    add_result(results, "Target", "INFO", hostname)

    # --------------------------------------
    # DNS AND PUBLIC IP ANALYSIS
    # --------------------------------------

    progress("Resolving DNS and checking IP addresses", 12)

    try:
        addresses = socket.getaddrinfo(hostname, None)
        unique_ips = sorted(set(item[4][0] for item in addresses))
        public_ips = []

        for ip in unique_ips:
            address = ipaddress.ip_address(ip)

            if not address.is_global:
                add_result(
                    results,
                    "Private IP Protection",
                    "FAIL",
                    f"Non-public address blocked: {ip}"
                )
                progress("Scan stopped: non-public IP address", 100)
                return results

            public_ips.append(ip)

        add_result(
            results,
            "IP Addresses",
            "PASS",
            ", ".join(public_ips)
        )

    except Exception as error:
        add_result(results, "DNS Resolution", "FAIL", error)
        progress("Scan stopped: DNS resolution failed", 100)
        return results

    # --------------------------------------
    # DNS RECORD ANALYSIS
    # --------------------------------------

    progress("Checking DNS records", 25)

    for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            answers = dns.resolver.resolve(
                hostname,
                record_type,
                lifetime=5
            )

            values = ", ".join(str(answer) for answer in answers)

            add_result(
                results,
                f"DNS {record_type}",
                "PASS",
                values
            )

        except dns.resolver.NXDOMAIN:
            add_result(
                results,
                f"DNS {record_type}",
                "INFO",
                "Domain does not exist"
            )

        except dns.resolver.NoAnswer:
            add_result(
                results,
                f"DNS {record_type}",
                "INFO",
                f"No {record_type} record is published for this domain"
            )

        except dns.resolver.LifetimeTimeout:
            add_result(
                results,
                f"DNS {record_type}",
                "INFO",
                "DNS lookup timed out"
            )

        except dns.resolver.NoNameservers:
            add_result(
                results,
                f"DNS {record_type}",
                "INFO",
                "DNS nameservers did not provide an answer"
            )

        except Exception as error:
            add_result(
                results,
                f"DNS {record_type}",
                "INFO",
                f"DNS lookup error: {error}"
            )

    # --------------------------------------
    # WHOIS ANALYSIS
    # --------------------------------------

    progress("Performing WHOIS lookup", 35)

    whois_analysis(hostname, results)

    # --------------------------------------
    # HTTP ANALYSIS
    # --------------------------------------

    progress("Connecting to website over HTTP or HTTPS", 45)

    response = None

    try:
        response = requests.get(
            target,
            timeout=10,
            allow_redirects=False,
            verify=True,
            headers={"User-Agent": "WebRecon-Pro/1.0"}
        )

        add_result(
            results,
            "HTTP Status",
            "PASS",
            f"HTTP {response.status_code}"
        )

        if 300 <= response.status_code < 400:
            add_result(
                results,
                "Redirect",
                "INFO",
                response.headers.get("Location", "Redirect detected")
            )

        # ----------------------------------
        # SECURITY HEADER ANALYSIS
        # ----------------------------------

        progress("Analyzing HTTP security headers", 60)

        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]

        for header in security_headers:
            if header in response.headers:
                add_result(
                    results,
                    header,
                    "PASS",
                    response.headers[header]
                )
            else:
                add_result(
                    results,
                    header,
                    "INFO",
                    "Header not detected"
                )

        server = response.headers.get("Server", "Not disclosed")
        add_result(results, "Server", "INFO", server)

        # ----------------------------------
        # COOKIE SECURITY ANALYSIS
        # ----------------------------------

        progress("Checking cookie security settings", 68)

        cookies = response.cookies

        if cookies:
            for cookie in cookies:
                rest = getattr(cookie, "_rest", {})

                httponly = any(
                    str(key).lower() == "httponly"
                    for key in rest
                )

                samesite = next(
                    (
                        value for key, value in rest.items()
                        if str(key).lower() == "samesite"
                    ),
                    "Not set"
                )

                flags = [
                    f"Secure: {'Yes' if cookie.secure else 'No'}",
                    f"HttpOnly: {'Yes' if httponly else 'No'}",
                    f"SameSite: {samesite}"
                ]

                add_result(
                    results,
                    f"Cookie: {cookie.name}",
                    "INFO",
                    "; ".join(flags)
                )
        else:
            add_result(
                results,
                "Cookies",
                "INFO",
                "No cookies detected in this response"
            )

        # ----------------------------------
        # HTML ANALYSIS
        # ----------------------------------

        progress("Analyzing website HTML and metadata", 76)

        soup = BeautifulSoup(response.text, "html.parser")

        title = (
            soup.title.string.strip()
            if soup.title and soup.title.string
            else "No title"
        )

        add_result(results, "Website Title", "PASS", title)

        add_result(
            results,
            "Links Found",
            "INFO",
            len(soup.find_all("a", href=True))
        )

        add_result(
            results,
            "Forms Found",
            "INFO",
            len(soup.find_all("form"))
        )

        # ----------------------------------
        # TECHNOLOGY DETECTION
        # ----------------------------------

        progress("Detecting publicly visible technologies", 83)

        technology_detection(response, soup, results)

    except requests.exceptions.SSLError as error:
        add_result(results, "HTTPS / SSL", "FAIL", error)

    except requests.exceptions.RequestException as error:
        add_result(results, "HTTP Request", "FAIL", error)

    finally:
        if response is not None:
            response.close()

    # --------------------------------------
    # SSL CERTIFICATE VERIFICATION
    # --------------------------------------

    progress("Verifying SSL certificate", 91)

    if parsed.scheme == "https":
        try:
            context = ssl.create_default_context()

            with socket.create_connection(
                (hostname, parsed.port or 443),
                timeout=10
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=hostname
                ) as secure_socket:

                    certificate = secure_socket.getpeercert()
                    issuer = certificate.get("issuer", ())
                    expiry = certificate.get("notAfter", "Unknown")

                    add_result(
                        results,
                        "SSL Certificate",
                        "PASS",
                        "Certificate verified"
                    )

                    add_result(
                        results,
                        "SSL Issuer",
                        "INFO",
                        str(issuer)
                    )

                    add_result(
                        results,
                        "SSL Expiry",
                        "INFO",
                        expiry
                    )

        except Exception as error:
            add_result(
                results,
                "SSL Certificate",
                "FAIL",
                error
            )

    else:
        add_result(
            results,
            "SSL Certificate",
            "INFO",
            "HTTPS was not used"
        )

    progress("Website scan completed", 100)

    return results

