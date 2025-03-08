import requests
from bs4 import BeautifulSoup

def check_vernability(url):
    # Make a request to the website
    try:
        response = requests.get(url)
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return

    # Check for server headers
    server_header = response.headers.get('Server')
    if server_header:
        print(f"Server header: {server_header}")
    else:
        print("Server header not found")

    # Check for X-Frame-Options
    x_frame_options = response.headers.get('X-Frame-Options')
    if x_frame_options:
        print(f"X-Frame-Options: {x_frame_options}")
    else:
        print("X-Frame-Options not found")

    # Check for X-XSS-Protection
    x_xss_protection = response.headers.get('X-XSS-Protection')
    if x_xss_protection:
        print(f"X-XSS-Protection: {x_xss_protection}")
    else:
        print("X-XSS-Protection not found")

    # Check for Content-Security-Policy
    content_security_policy = response.headers.get('Content-Security-Policy')
    if content_security_policy:
        print(f"Content-Security-Policy: {content_security_policy}")
    else:
        print("Content-Security-Policy not found")

    # Check for Strict-Transport-Security
    strict_transport_security = response.headers.get('Strict-Transport-Security')
    if strict_transport_security:
        print(f"Strict-Transport-Security: {strict_transport_security}")
    else:
        print("Strict-Transport-Security not found")

    # Check for Referrer-Policy
    referrer_policy = response.headers.get('Referrer-Policy')
    if referrer_policy:
        print(f"Referrer-Policy: {referrer_policy}")
    else:
        print("Referrer-Policy not found")

    # Check for Feature-Policy
    feature_policy = response.headers.get('Feature-Policy')
    if feature_policy:
        print(f"Feature-Policy: {feature_policy}")
    else:
        print("Feature-Policy not found")

    # Check for Content-Type
    content_type = response.headers.get('Content-Type')
    if content_type:
        print(f"Content-Type: {content_type}")
    else:
        print("Content-Type not found")

    # Check for CSP implementation
    soup = BeautifulSoup(response.text, 'html.parser')
    csp_implemented = False
    for script in soup.find_all('script'):
        if script.get('src'):
            csp_implemented = True
            break
    print(f"CSP implemented: {csp_implemented}")

    # Check for cookie security
    cookie_secure = False
    cookie_httponly = False
    cookie_samesite = False
    for cookie in response.cookies:
        if cookie.secure:
            cookie_secure = True
        if cookie.has_nonstandard_attr('httponly'):
            cookie_httponly = True
        if cookie.has_nonstandard_attr('samesite'):
            cookie_samesite = True
    print(f"Cookie secure: {cookie_secure}")
    print(f"Cookie httponly: {cookie_httponly}")
    print(f"Cookie samesite: {cookie_samesite}")

    # Check for clickjacking protection
    iframe_protection = False
    for iframe in soup.find_all('iframe'):
        if iframe.get('sandbox') or iframe.get('allow') or iframe.get('allowfullscreen'):
            iframe_protection = True
            break
    print(f"Clickjacking protection: {iframe_protection}")

    # Check for cross-site scripting (XSS) protection
    xss_protection = False
    for input_tag in soup.find_all('input'):
        if input_tag.get('type') == 'text' and not input_tag.get('oninput'):
            xss_protection = True
            break
    print(f"XSS protection: {xss_protection}")

    # Check for SQL injection protection
    sql_injection_protection = False
    for form in soup.find_all('form'):
        if form.get('action'):
            sql_injection_protection = True
            break
    print(f"SQL injection protection: {sql_injection_protection}")

    # Check for CSRF protection
    csrf_protection = False
    for form in soup.find_all('form'):
        if form.get('action') and form.get('method') == 'post':
            if form.find('input', {'type': 'hidden', 'name': 'csrf_token'}):
                csrf_protection = True
                break
    print(f"CSRF protection: {csrf_protection}")

    # Check for directory listing
    directory_listing = False
    try:
        response = requests.get(url + '/')
        if response.status_code == 200:
            directory_listing = True
    except requests.exceptions.RequestException:
        pass
    print(f"Directory listing: {directory_listing}")

def import_websites(file_path):
    try:
        with open(file_path, 'r') as file:
            urls = file.read().splitlines()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return

    for url in urls:
        print(f"\nChecking vernability for: {url}")
        check_vernability(url)

# Example usage
file_path = 'websites.txt'
import_websites(file_path)