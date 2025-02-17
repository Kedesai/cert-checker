import requests
import base64
import json
import ssl
import socket
import datetime
import os
import logging
from jira import JIRA
from jira import JIRA, JIRAError

# Configure logging
logging.basicConfig(level=logging.INFO)

# Jira credentials from environment variables
JIRA_USERNAME = os.getenv("JIRA_USERNAME")
JIRA_API_TOKEN = os.getenv("JIRA_API_TOKEN")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY")
JIRA_BASE_URL = os.getenv("JIRA_BASE_URL")

# Log the environment variables to ensure they are set correctly
logging.info(f"JIRA_USERNAME: {JIRA_USERNAME}")
logging.info(f"JIRA_API_TOKEN: {JIRA_API_TOKEN}")
logging.info(f"JIRA_PROJECT_KEY: {JIRA_PROJECT_KEY}")
logging.info(f"JIRA_BASE_URL: {JIRA_BASE_URL}")

# Confluence credentials from environment variables
CONFLUENCE_USERNAME = os.getenv("CONFLUENCE_USERNAME")
CONFLUENCE_API_TOKEN = os.getenv("CONFLUENCE_API_TOKEN")
CONFLUENCE_PAGE_ID = os.getenv("CONFLUENCE_PAGE_ID")
CONFLUENCE_BASE_URL = os.getenv("CONFLUENCE_BASE_URL")

# Log the Confluence environment variables to ensure they are set correctly
logging.info(f"CONFLUENCE_USERNAME: {CONFLUENCE_USERNAME}")
logging.info(f"CONFLUENCE_API_TOKEN: {CONFLUENCE_API_TOKEN}")
logging.info(f"CONFLUENCE_PAGE_ID: {CONFLUENCE_PAGE_ID}")
logging.info(f"CONFLUENCE_BASE_URL: {CONFLUENCE_BASE_URL}")


# Certificate domains (replace with actual data)
certificate_domains = ["google.com", "microsoft.com", "starbucks.com", "youtube.com", "yahoo.com", "att.com", "chatgpt.com", "reddit.com", "verizon.com", "live.com", "linkedin.com", "office.com",
 "bing.com", "max.com", "discord.com", "samsung.com", "twitch.tv", "weather.com", "quora.com", "duckduckgo.com", "fandom.com", "sharepoint.com"]

def check_certificate_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssl_sock:
                cert = ssl_sock.getpeercert()
                #expiry_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                expiry_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                expiry_date = expiry_date.replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)  # Ensure now is also offset-aware
                days_remaining = (expiry_date - now).days
                #days_remaining = (expiry_date - datetime.datetime.now(datetime.timezone.utc)).days
                logging.info(f"Certificate for {domain} expires in {days_remaining} days")
                return days_remaining
    except (ssl.SSLError, socket.gaierror, socket.timeout) as e:
        logging.error(f"Network-related error checking certificate for {domain}: {e}")
        return None
    except Exception as e:
        logging.exception(f"Unexpected error checking certificate for {domain}: {e}")
        return None
   
def get_existing_jira_issue(domain):
    url = f"{JIRA_BASE_URL}/search?jql=summary~'Certificate for {domain} is expiring within'"
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{JIRA_USERNAME}:{JIRA_API_TOKEN}'.encode()).decode()}",
        "Content-Type": "application/json",
    }
    existing_issue = requests.get(url, headers=headers)
    if existing_issue.status_code == 200 and existing_issue.json().get("total") > 0:
        return existing_issue.json()["issues"][0]["key"]
    else:
        return None

def create_jira_issue(domain, days_remaining):
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
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        print(f"Jira story created successfully for {domain}")
        return response.json()["key"]  # Return issue key for potential updates
    except requests.RequestException as e:
        print(f"Error creating Jira story for {domain}: {e}")
        return None

def update_jira_issue(issue_key, days_remaining, domain):
    url = f"{JIRA_BASE_URL}/issue/{issue_key}/comment"  # Correct endpoint for adding comments
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
        print(f"Jira issue {issue_key} updated with comment.")
    except requests.RequestException as e:
        print(f"Error updating Jira issue {issue_key} comment: {e}")


def sort_certificates_by_days_remaining(certificates):
    """Sorts a list of certificates by the number of days remaining to expire in ascending order.

    Args:
        certificates: A list of dictionaries where each dictionary represents
                      a certificate and contains a 'days_remaining' key.

    Returns:
        A new list of dictionaries sorted by days remaining (ascending).
    """
    return sorted(certificates, key=lambda x: x.get("days_remaining", float("inf")))




def get_confluence_page_content():
    url = f"{CONFLUENCE_BASE_URL}/{CONFLUENCE_PAGE_ID}"
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{CONFLUENCE_USERNAME}:{CONFLUENCE_API_TOKEN}'.encode()).decode()}",
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def update_confluence_page_content(existing_content, new_content):
    url = f"{CONFLUENCE_BASE_URL}/{CONFLUENCE_PAGE_ID}"
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{CONFLUENCE_USERNAME}:{CONFLUENCE_API_TOKEN}'.encode()).decode()}",
        "Content-Type": "application/json",
    }
    payload = {
        "version": {"number": existing_content["version"]["number"] + 1},
        "title": existing_content["title"],
        "type": existing_content["type"],
        "body": {"storage": {"value": new_content, "representation": "storage"}},
    }
    try:
        response = requests.put(url, headers=headers, json=payload)
        response.raise_for_status()
        print("Confluence page updated successfully!")
    except requests.RequestException as e:
        print(f"Error updating Confluence page: {e}")

def is_certificate_recently_issued(not_before_date, threshold_days=30):
    """
    Checks if the certificate issuance date (not_before_date) is within the specified threshold_days.

    Args:
        not_before_date (str): The certificate issuance date in YYYY-MM-DD format.
        threshold_days (int): Number of days to consider as "recently issued" (default is 30).

    Returns:
        bool: True if the certificate is recently issued, False otherwise.
    """


#def close_jira_issue(jira, issue_key, domain):
#  """Closes a Jira issue.

 # Args:
 #   jira: A JIRA object to interact with the Jira server.
 #   issue_key: The key of the Jira issue to be closed.
 # """
  # Get the issue
#  issue = jira.issue(issue_key)

# Find the transition ID for the closed state
#  closed_transition_id = [transition.id for transition in issue.transitions if transition.name == "Closed"][0]

# Close the issue
#  try:
#      closure_url = f"{jira.server}/{issue.key}/transition"
#      print(f"Closing issue using URL: {closure_url}")
#      jira.transition_issue(issue, closed_transition_id)
#      print(f"Jira issue {issue_key} closed for {domain}.")
#  except JIRAError as e:
#      print(f"Error closing Jira issue {issue_key}: {e}")


#jira = JIRA(JIRA_BASE_URL, basic_auth=(JIRA_USERNAME, JIRA_API_TOKEN))

def close_jira_issue(jira, domain, issue_key, days_remaining):
    url = f"{JIRA_BASE_URL}/transition"
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{JIRA_USERNAME}:{JIRA_API_TOKEN}'.encode()).decode()}",
        "Content-Type": "application/json",
    }
    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": f"Certificate for {domain} is updated and {days_remaining} days",
            "description": f"The SSL certificate for {domain} has been updated and {days_remaining} days.",
            "issuetype": {"name": "Task"},
        }
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        print(f"Jira story closed successfully for {domain}")
        return response.json()["key"]  # Return issue key for potential updates
    except requests.RequestException as e:
        print(f"Error closing Jira story for {domain}: {e}")
        return None

def get_server_certificate(domain):
    response = requests.get(f"https://{domain}", verify=True)
    return response.raw.read()

def main():
    table_rows = ""
    certificate_data = []

    for domain in certificate_domains:
        days_remaining = check_certificate_expiry(domain)
        not_before_date = "2023-01-01"  # Replace with the desired threshold date
        color = "red" if days_remaining is not None and days_remaining <= 30 else "green"
        table_row = f"<tr><td>{domain}</td><td style='color: {color}'>{days_remaining if days_remaining is not None else 'N/A'}</td></tr>"
        certificate_data.append({"domain": domain, "days_remaining": days_remaining})

        if days_remaining is not None and days_remaining <= 30:
            # Check if Jira issue exists
            issue_key = get_existing_jira_issue(domain)
            if issue_key:
                update_jira_issue(issue_key, days_remaining, domain)
            else:
                issue_key = create_jira_issue(domain, days_remaining)

        # Check if the certificate is recently issued (adjust threshold as needed)
        if days_remaining is not None and days_remaining > 300:
            issue_key = get_existing_jira_issue(domain)
            if issue_key:
                # Retrieve certificate details
                cert_data = ssl.get_server_certificate(domain)

                # Print the output for debugging (uncomment if needed)
                # print(f"Retrieved certificate data: {cert_data}")

                # Handle potential change in function behavior
                try:
                    host, port, cert_data = cert_data  # Try unpacking as a tuple
                except ValueError:
                    pass  # If unpacking fails, handle as a single string

                # Extract notBefore and notAfter dates
                cert_info = ssl.DER_to_PEM_certificate(cert_data)
                cert_data = ssl.load_pem_x509_certificate(cert_info)

                not_before = cert_data.notBefore.strftime("%Y-%m-%d")
                not_after = cert_data.notAfter.strftime("%Y-%m-%d")

                # Check if recently issued
                if is_certificate_recently_issued(not_before, notAfter):
                    close_jira_issue(jira, issue_key, domain)
                    print(f"Jira issue closed for {domain} as certificate is recently issued.")
                else:
                    print(f"Jira issue for {domain} not closed as certificate is not recently issued.")
            else:
                print(f"No existing Jira issue found for {domain}.")
        else:
            print(f"Days remaining is None or less than 300 for {domain}.")

#def main():
#    table_rows = ""
#    certificate_data = []
#    for domain in certificate_domains:
#        days_remaining = check_certificate_expiry(domain)
#        not_before_date = "2023-01-01"
#        color = "red" if days_remaining is not None and days_remaining <= 30 else "green"
#        table_row = f"<tr><td>{domain}</td><td style='color: {color}'>{days_remaining if days_remaining is not None else 'N/A'}</td></tr>"
#        certificate_data.append({"domain": domain, "days_remaining": days_remaining}) # new line added
     #   table_rows += table_row

#        if days_remaining is not None and days_remaining <= 30:
#            # Check if Jira issue exists
#            issue_key = get_existing_jira_issue(domain)
#            if issue_key:
#                update_jira_issue(issue_key, days_remaining, domain)
#            else:
#                issue_key = create_jira_issue(domain, days_remaining)

#        if days_remaining is not None and days_remaining > 300:
        #  Get existing Jira issue
#            issue_key = get_existing_jira_issue(domain)
#            if issue_key:
            # Check if the certificate is recently issued
#                if is_certificate_recently_issued(not_before_date):
#                # Close the Jira issue
#                    close_jira_issue(jira, issue_key)
#                    print(f"Jira issue closed for {domain} as certificate is recently issued.")
#                else:
#                    print(f"Jira issue for {domain} not closed as certificate is not recently issued.")
#            else:
#                print(f"No existing Jira issue found for {domain}.")
#        else:
#            print(f"Days remaining is None or less than 300 for {domain}.")


      #  if days_remaining is not None and days_remaining[0] > 300:
      #      issue_key = get_existing_jira_issue(domain)
      #      if issue_key:
      #          if is_certificate_recently_issued(not_before_date):
      #         # if close_jira_issue(not_before_date, issue_key, domain):
      #             close_jira_issue(jira, issue_key)
      #             print(f"Jira issue closed for {domain} as certificate is recently issued.")
      #          else:
      #              print(f"Jira issue for {domain} not closed as certificate is not recently issued.")

    #Sort certificates by days remaining in ascending order
    sorted_certificates = sort_certificates_by_days_remaining(certificate_data) # new line added

    # Generate table rows for the Confluence page
    for cert in sorted_certificates:
        table_rows += f"<tr><td>{cert['domain']}</td><td>{cert['days_remaining'] if cert['days_remaining'] is not None else 'N/A'}</td></tr>"

    new_content = f"""
        <h2>Certificate Information</h2>
        <table>
            {table_rows}
        </table>
    """

    existing_content = get_confluence_page_content()
    update_confluence_page_content(existing_content, new_content)

if __name__ == "__main__":
    main()
# Confluence credentials (replace with your actual values)
CONFLUENCE_USERNAME = "Confluence-username@somewhere.com"
CONFLUENCE_API_TOKEN = "Confluence-api-token"
CONFLUENCE_PAGE_ID = "PageID where you want to create the jira story"
CONFLUENCE_BASE_URL = "https://site.atlassian.net/wiki/rest/api/content"

# Jira credentials (replace with your actual values)
JIRA_USERNAME = "username@somewhere.com"
JIRA_API_TOKEN = "Jira-api-Token"
JIRA_PROJECT_KEY = "your-jira-project-key"
JIRA_BASE_URL = "https://site.atlassian.net/rest/api/2"


# Certificate domains (replace with actual data)
certificate_domains = ["google.com", "microsoft.com", "starbucks.com", "youtube.com", "baidu.com", "wikipedia.org", "yahoo.com", "att.com", "chatgpt.com", "reddit.com", "verizon.com", "live.com", "linkedin.com", "office.com", 
 "bing.com", "max.com", "discord.com", "samsung.com", "microsoft.com", "twitch.tv", "weather.com", "quora.com", "roblox.com", "duckduckgo.com", "fandom.com", "sharepoint.com", "qq.com"]

def check_certificate_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssl_sock:
                cert = ssl_sock.getpeercert()
                #expiry_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                expiry_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                expiry_date = expiry_date.replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)  # Ensure now is also offset-aware
                days_remaining = (expiry_date - now).days
                #days_remaining = (expiry_date - datetime.datetime.now(datetime.timezone.utc)).days
                logging.info(f"Certificate for {domain} expires in {days_remaining} days")
                return days_remaining
    except (ssl.SSLError, socket.gaierror, socket.timeout) as e:
        logging.error(f"Network-related error checking certificate for {domain}: {e}")
        return None
    except Exception as e:
        logging.exception(f"Unexpected error checking certificate for {domain}: {e}")
        return None
    
def get_existing_jira_issue(domain):
    url = f"{JIRA_BASE_URL}/search?jql=summary~'Certificate for {domain} is expiring within'"
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{JIRA_USERNAME}:{JIRA_API_TOKEN}'.encode()).decode()}",
        "Content-Type": "application/json",
    }
    existing_issue = requests.get(url, headers=headers)
    if existing_issue.status_code == 200 and existing_issue.json().get("total") > 0:
        return existing_issue.json()["issues"][0]["key"]
    else:
        return None

def create_jira_issue(domain, days_remaining):
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
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        print(f"Jira story created successfully for {domain}")
        return response.json()["key"]  # Return issue key for potential updates
    except requests.RequestException as e:
        print(f"Error creating Jira story for {domain}: {e}")
        return None

def update_jira_issue(issue_key, days_remaining, domain):
    url = f"{JIRA_BASE_URL}/issue/{issue_key}/comment"  # Correct endpoint for adding comments
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
        print(f"Jira issue {issue_key} updated with comment.")
    except requests.RequestException as e:
        print(f"Error updating Jira issue {issue_key} comment: {e}")


def sort_certificates_by_days_remaining(certificates):
    """Sorts a list of certificates by the number of days remaining to expire in ascending order.

    Args:
        certificates: A list of dictionaries where each dictionary represents
                      a certificate and contains a 'days_remaining' key.

    Returns:
        A new list of dictionaries sorted by days remaining (ascending).
    """
    return sorted(certificates, key=lambda x: x.get("days_remaining", float("inf")))




def get_confluence_page_content():
    url = f"{CONFLUENCE_BASE_URL}/{CONFLUENCE_PAGE_ID}"
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{CONFLUENCE_USERNAME}:{CONFLUENCE_API_TOKEN}'.encode()).decode()}",
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def update_confluence_page_content(existing_content, new_content):
    url = f"{CONFLUENCE_BASE_URL}/{CONFLUENCE_PAGE_ID}"
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{CONFLUENCE_USERNAME}:{CONFLUENCE_API_TOKEN}'.encode()).decode()}",
        "Content-Type": "application/json",
    }
    payload = {
        "version": {"number": existing_content["version"]["number"] + 1},
        "title": existing_content["title"],
        "type": existing_content["type"],
        "body": {"storage": {"value": new_content, "representation": "storage"}},
    }
    try:
        response = requests.put(url, headers=headers, json=payload)
        response.raise_for_status()
        print("Confluence page updated successfully!")
    except requests.RequestException as e:
        print(f"Error updating Confluence page: {e}")

def is_certificate_recently_issued(not_before_date, threshold_days=30):
    """
    Checks if the certificate issuance date (not_before_date) is within the specified threshold_days.

    Args:
        not_before_date (str): The certificate issuance date in YYYY-MM-DD format.
        threshold_days (int): Number of days to consider as "recently issued" (default is 30).

    Returns:
        bool: True if the certificate is recently issued, False otherwise.
    """


def close_jira_issue(jira, domain, issue_key, days_remaining):
    url = f"{JIRA_BASE_URL}/transition"
    headers = {
        "Authorization": f"Basic {base64.b64encode(f'{JIRA_USERNAME}:{JIRA_API_TOKEN}'.encode()).decode()}",
        "Content-Type": "application/json",
    }
    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": f"Certificate for {domain} is updated and {days_remaining} days",
            "description": f"The SSL certificate for {domain} has been updated and {days_remaining} days.",
            "issuetype": {"name": "Task"},
        }
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        print(f"Jira story closed successfully for {domain}")
        return response.json()["key"]  # Return issue key for potential updates
    except requests.RequestException as e:
        print(f"Error closing Jira story for {domain}: {e}")
        return None

def get_server_certificate(domain):
    response = requests.get(f"https://{domain}", verify=True)
    return response.raw.read()

def main():
    table_rows = ""
    certificate_data = []

    for domain in certificate_domains:
        days_remaining = check_certificate_expiry(domain)
        not_before_date = "2023-01-01"  # Replace with the desired threshold date
        color = "red" if days_remaining is not None and days_remaining <= 30 else "green"
        table_row = f"<tr><td>{domain}</td><td style='color: {color}'>{days_remaining if days_remaining is not None else 'N/A'}</td></tr>"
        certificate_data.append({"domain": domain, "days_remaining": days_remaining})

        if days_remaining is not None and days_remaining <= 30:
            # Check if Jira issue exists
            issue_key = get_existing_jira_issue(domain)
            if issue_key:
                update_jira_issue(issue_key, days_remaining, domain)
            else:
                issue_key = create_jira_issue(domain, days_remaining)

        # Check if the certificate is recently issued (adjust threshold as needed)
        if days_remaining is not None and days_remaining > 300:
            issue_key = get_existing_jira_issue(domain)
            if issue_key:
                # Retrieve certificate details
                cert_data = ssl.get_server_certificate(domain)

                # Print the output for debugging (uncomment if needed)
                # print(f"Retrieved certificate data: {cert_data}")

                # Handle potential change in function behavior
                try:
                    host, port, cert_data = cert_data  # Try unpacking as a tuple
                except ValueError:
                    pass  # If unpacking fails, handle as a single string

                # Extract notBefore and notAfter dates
                cert_info = ssl.DER_to_PEM_certificate(cert_data)
                cert_data = ssl.load_pem_x509_certificate(cert_info)

                not_before = cert_data.notBefore.strftime("%Y-%m-%d")
                not_after = cert_data.notAfter.strftime("%Y-%m-%d")

                # Check if recently issued
                if is_certificate_recently_issued(not_before, notAfter):
                    close_jira_issue(jira, issue_key, domain)
                    print(f"Jira issue closed for {domain} as certificate is recently issued.")
                else:
                    print(f"Jira issue for {domain} not closed as certificate is not recently issued.")
            else:
                print(f"No existing Jira issue found for {domain}.")
        else:
            print(f"Days remaining is None or less than 300 for {domain}.")
    #Sort certificates by days remaining in ascending order
    sorted_certificates = sort_certificates_by_days_remaining(certificate_data) # new line added

    # Generate table rows for the Confluence page
    for cert in sorted_certificates:
        table_rows += f"<tr><td>{cert['domain']}</td><td>{cert['days_remaining'] if cert['days_remaining'] is not None else 'N/A'}</td></tr>"

    new_content = f"""
        <h2>Certificate Information</h2>
        <table>
            {table_rows}
        </table>
    """

    existing_content = get_confluence_page_content()
    update_confluence_page_content(existing_content, new_content)

if __name__ == "__main__":
    main()
