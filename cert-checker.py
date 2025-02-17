import os
import requests
import base64
import ssl
import socket
import datetime
import logging
from jira import JIRA

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load environment variables
JIRA_USERNAME = os.getenv("JIRA_USERNAME")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY")
JIRA_BASE_URL = os.getenv("JIRA_BASE_URL")

CONFLUENCE_USERNAME = os.getenv("CONFLUENCE_USERNAME")
CONFLUENCE_API_TOKEN = os.getenv("CONFLUENCE_API_TOKEN")
CONFLUENCE_PAGE_ID = os.getenv("CONFLUENCE_PAGE_ID")
CONFLUENCE_BASE_URL = os.getenv("CONFLUENCE_BASE_URL")

# Log environment variables for debugging
logging.info(f"JIRA_USERNAME: {JIRA_USERNAME}")
logging.info(f"JIRA_PROJECT_KEY: {JIRA_PROJECT_KEY}")
logging.info(f"JIRA_BASE_URL: {JIRA_BASE_URL}")
logging.info(f"CONFLUENCE_USERNAME: {CONFLUENCE_USERNAME}")
logging.info(f"CONFLUENCE_PAGE_ID: {CONFLUENCE_PAGE_ID}")
logging.info(f"CONFLUENCE_BASE_URL: {CONFLUENCE_BASE_URL}")

# Certificate domains to check
CERTIFICATE_DOMAINS = [
    "google.com", "microsoft.com", "starbucks.com", "youtube.com", "yahoo.com",
    "att.com", "chatgpt.com", "reddit.com", "verizon.com", "live.com",
    "linkedin.com", "office.com", "bing.com", "max.com", "discord.com",
    "samsung.com", "twitch.tv", "weather.com", "quora.com", "duckduckgo.com",
    "fandom.com", "sharepoint.com"
]

def check_certificate_expiry(domain):
    """Check the SSL certificate expiry for a given domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssl_sock:
                cert = ssl_sock.getpeercert()
                expiry_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                expiry_date = expiry_date.replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                days_remaining = (expiry_date - now).days
                logging.info(f"Certificate for {domain} expires in {days_remaining} days")
                return days_remaining
    except (ssl.SSLError, socket.gaierror, socket.timeout) as e:
        logging.error(f"Network-related error checking certificate for {domain}: {e}")
        return None
    except Exception as e:
        logging.exception(f"Unexpected error checking certificate for {domain}: {e}")
        return None

def get_existing_jira_issue(domain):
    """Check if a Jira issue already exists for the domain."""
    url = f"{JIRA_BASE_URL}/rest/api/2/search"
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{JIRA_USERNAME}:{JIRA_API_TOKEN}'.encode()).decode()}",
        "Content-Type": "application/json",
    }
    jql = f"project = {JIRA_PROJECT_KEY} AND summary ~ 'Certificate for {domain} is expiring within'"
    response = requests.get(url, headers=headers, params={"jql": jql})
    if response.status_code == 200 and response.json().get("total", 0) > 0:
        return response.json()["issues"][0]["key"]
    return None

def create_jira_issue(domain, days_remaining):
    """Create a new Jira issue for an expiring certificate."""
    url = f"{JIRA_BASE_URL}/rest/api/2/issue"
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{JIRA_USERNAME}:{JIRA_API_TOKEN}'.encode()).decode()}",
        "Content-Type": "application/json",
    }
    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": f"Certificate for {domain} is expiring within {days_remaining} days",
            "description": f"The SSL certificate for {domain} will expire in {days_remaining} days.",
            "issuetype": {"name": "Task"},
        }
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        logging.info(f"Jira issue created successfully for {domain}")
        return response.json()["key"]
    except requests.RequestException as e:
        logging.error(f"Error creating Jira issue for {domain}: {e}")
        return None

def update_jira_issue(issue_key, days_remaining, domain):
    """Add a comment to an existing Jira issue."""
    url = f"{JIRA_BASE_URL}/rest/api/2/issue/{issue_key}/comment"
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{JIRA_USERNAME}:{JIRA_API_TOKEN}'.encode()).decode()}",
        "Content-Type": "application/json",
    }
    payload = {
        "body": f"Certificate for {domain} will expire in {days_remaining} days. Action required."
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        logging.info(f"Comment added to Jira issue {issue_key}")
    except requests.RequestException as e:
        logging.error(f"Error updating Jira issue {issue_key}: {e}")

def close_jira_issue(issue_key):
    """Close a Jira issue."""
    url = f"{JIRA_BASE_URL}/rest/api/2/issue/{issue_key}/transitions"
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{JIRA_USERNAME}:{JIRA_API_TOKEN}'.encode()).decode()}",
        "Content-Type": "application/json",
    }
    payload = {
        "transition": {"id": "31"}  # Replace "31" with the ID of your "Close" transition
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        logging.info(f"Jira issue {issue_key} closed successfully")
    except requests.RequestException as e:
        logging.error(f"Error closing Jira issue {issue_key}: {e}")

def update_confluence_page(content):
    """Update the Confluence page with the certificate information."""
    url = f"{CONFLUENCE_BASE_URL}/{CONFLUENCE_PAGE_ID}"
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{CONFLUENCE_USERNAME}:{CONFLUENCE_API_TOKEN}'.encode()).decode()}",
        "Content-Type": "application/json",
    }

    # Log the request URL and headers for debugging
    logging.info(f"Request URL: {url}")
    logging.info(f"Request Headers: {headers}")

    try:
        # Fetch existing content
        response = requests.get(url, headers=headers)
        logging.info(f"Response Status Code: {response.status_code}")
        logging.info(f"Response Content: {response.text}")

        # Check if the response is valid JSON
        if response.status_code != 200:
            logging.error(f"Failed to fetch Confluence page. Status Code: {response.status_code}")
            return

        existing_content = response.json()

        # Prepare payload for update
        version = existing_content["version"]["number"] + 1
        payload = {
            "version": {"number": version},
            "title": existing_content["title"],
            "type": "page",
            "body": {
                "storage": {
                    "value": content,
                    "representation": "storage"
                }
            }
        }

        # Update the page
        update_response = requests.put(url, headers=headers, json=payload)
        logging.info(f"Update Response Status Code: {update_response.status_code}")
        logging.info(f"Update Response Content: {update_response.text}")

        if update_response.status_code == 200:
            logging.info("Confluence page updated successfully")
        else:
            logging.error(f"Failed to update Confluence page. Status Code: {update_response.status_code}")

    except requests.RequestException as e:
        logging.error(f"Error updating Confluence page: {e}")
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON response from Confluence API: {e}")

def main():
    certificate_data = []
    for domain in CERTIFICATE_DOMAINS:
        days_remaining = check_certificate_expiry(domain)
        if days_remaining is not None:
            certificate_data.append({"domain": domain, "days_remaining": days_remaining})
            if days_remaining <= 30:
                issue_key = get_existing_jira_issue(domain)
                if issue_key:
                    update_jira_issue(issue_key, days_remaining, domain)
                else:
                    create_jira_issue(domain, days_remaining)
            elif days_remaining > 365:
                issue_key = get_existing_jira_issue(domain)
                if issue_key:
                    close_jira_issue(issue_key)

    # Sort certificates by days remaining
    sorted_certificates = sorted(certificate_data, key=lambda x: x["days_remaining"])

    # Generate Confluence page content
    table_rows = "".join(
        f"<tr><td>{cert['domain']}</td><td>{cert['days_remaining']}</td></tr>"
        for cert in sorted_certificates
    )
    new_content = f"""
        <h2>Certificate Expiry Information</h2>
        <table>
            <tr><th>Domain</th><th>Days Remaining</th></tr>
            {table_rows}
        </table>
    """
    update_confluence_page(new_content)

if __name__ == "__main__":
    main()

