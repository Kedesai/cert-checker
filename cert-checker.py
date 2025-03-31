import os
import requests
import base64
import ssl
import socket
import datetime
import logging
import json
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
    "fandom.com", "sharepoint.com", "cnn.com", "wikipedia.org", "ebay.com", "craigslist.org",
    "nytimes.com", "github.com", "stackoverflow.com", "bbc.co.uk", "imdb.com",
    "hulu.com", "pinterest.com", "target.com", "bestbuy.com", "costco.com",
    "lowes.com", "homeDepot.com", "walmart.com", "amazon.com", "apple.com",
    "paypal.com", "bankofamerica.com", "chase.com", "capitalone.com", "discover.com",
    "wellsfargo.com", "citi.com", "americanexpress.com", "usbank.com", "ally.com",
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
    url = f"{JIRA_BASE_URL}/issue"
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

    # Log the request URL, headers, and payload for debugging
    logging.info(f"Create Jira Issue Request URL: {url}")
    logging.info(f"Create Jira Issue Headers: {headers}")
    logging.info(f"Create Jira Issue Payload: {payload}")

    try:
        response = requests.post(url, headers=headers, json=payload)
        logging.info(f"Create Jira Issue Response Status Code: {response.status_code}")
        logging.info(f"Create Jira Issue Response Content: {response.text}")

        if response.status_code == 201:
            logging.info(f"Jira issue created successfully for {domain}")
            return response.json()["key"]
        else:
            logging.error(f"Failed to create Jira issue for {domain}. Status Code: {response.status_code}")
            return None
    except requests.RequestException as e:
        logging.error(f"Error creating Jira issue for {domain}: {e}")
        return None

def update_jira_issue(issue_key, days_remaining, domain):
    """Add a comment to an existing Jira issue."""
    url = f"{JIRA_BASE_URL}/issue/{issue_key}/comment"
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{JIRA_USERNAME}:{JIRA_API_TOKEN}'.encode()).decode()}",
        "Content-Type": "application/json",
    }
    payload = {
        "body": f"Certificate for {domain} will expire in {days_remaining} days. Action required."
    }

    # Log the request URL, headers, and payload for debugging
    logging.info(f"Update Jira Issue Request URL: {url}")
    logging.info(f"Update Jira Issue Headers: {headers}")
    logging.info(f"Update Jira Issue Payload: {payload}")

    try:
        response = requests.post(url, headers=headers, json=payload)
        logging.info(f"Update Jira Issue Response Status Code: {response.status_code}")
        logging.info(f"Update Jira Issue Response Content: {response.text}")

        if response.status_code == 201:
            logging.info(f"Comment added to Jira issue {issue_key}")
        else:
            logging.error(f"Failed to update Jira issue {issue_key}. Status Code: {response.status_code}")
    except requests.RequestException as e:
        logging.error(f"Error updating Jira issue {issue_key}: {e}")

def transition_renewed_cert_issues(domain, days_remaining, issue_key):
    """
    Transition issues to Done if:
    - Certificate has >300 days remaining
    - Was renewed in last 10 days (for 1-year certificates)
    - Issue is in Open/In Progress status
    """
    try:
        # Calculate renewal date (assuming 1-year certificates)
        now = datetime.datetime.now(datetime.timezone.utc)
        expiry_date = now + datetime.timedelta(days=days_remaining)
        renewal_date = expiry_date - datetime.timedelta(days=365)
        
        # Check conditions
        if days_remaining <= 300:
            logging.info(f"Issue {issue_key} not eligible - only {days_remaining} days remaining")
            return False
            
        if (now - renewal_date).days > 10:
            logging.info(f"Issue {issue_key} not eligible - last renewed {(now - renewal_date).days} days ago")
            return False

        # Get issue details
        jira = JIRA(
            server=JIRA_BASE_URL,
            basic_auth=(JIRA_USERNAME, JIRA_API_TOKEN)
        )

        issue = jira.issue(issue_key)
        current_status = issue.fields.status.name.lower()
        
        if current_status not in ['open', 'in progress']:
            logging.info(f"Issue {issue_key} not eligible - current status: {current_status}")
            return False
        
        # Find and execute transition
        transitions = jira.transitions(issue_key)
        done_transition = next(
            (t for t in transitions if t['name'].lower() == 'done'),
            None
        )
        
        if not done_transition:
            logging.error(f"No 'Done' transition found for {issue_key}")
            return False
        
        jira.transition_issue(
            issue_key,
            done_transition['id'],
            fields={'resolution': {'name': 'Done'}}
        )
        
        # Add informative comment
        comment = f"""Certificate automatically transitioned to Done because:
        - Renewed on {renewal_date.date()} (within last 10 days)
        - Now has {days_remaining} days remaining
        - Previous status: {current_status}"""
        jira.add_comment(issue_key, comment)
        
        logging.info(f"Successfully transitioned {issue_key} to Done")
        return True
        
    except Exception as e:
        logging.error(f"Error processing {issue_key}: {str(e)}")
        return False


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
            issue_key = get_existing_jira_issue(domain)
            
            if days_remaining <= 30:
                if issue_key:
                    update_jira_issue(issue_key, days_remaining, domain)
                else:
                    create_jira_issue(domain, days_remaining)
            elif days_remaining > 300 and issue_key:  # Changed from 365 to 300
                transition_renewed_cert_issues(domain, days_remaining, issue_key)

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