import os
import base64
import re
import logging
from datetime import datetime, timedelta

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# Define the required scopes
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/spreadsheets"
]

# Google Sheets setup
SHEET_ID = "YOUR_SHEET_ID"  # Update this with your actual Sheet ID
SHEET_NAME = "Sheet1"

# Set up logging
logging.basicConfig(
    filename='email_extraction.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def authenticate_google():
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    gmail_service = build("gmail", "v1", credentials=creds)
    sheets_service = build("sheets", "v4", credentials=creds)
    return gmail_service, sheets_service

def extract_name_company_email(from_header):
    match = re.match(r'^"?(.+?)"?\s*<(.+?)>$', from_header)
    if match:
        name = match.group(1).strip()
        email_addr = match.group(2).strip()
        company = "Unknown"
        return name, company, email_addr
    return "Unknown", "Unknown", from_header

def should_skip_email(subject, from_email, skip_keywords, skip_domains):
    if any(keyword.lower() in subject.lower() for keyword in skip_keywords):
        return True
    domain = from_email.split('@')[-1].lower()
    if any(domain.endswith(skip_domain) for skip_domain in skip_domains):
        return True
    return False

def extract_body(payload):
    body = ""
    if "parts" in payload:
        for part in payload["parts"]:
            if part.get("mimeType") == "text/plain":
                data = part.get("body", {}).get("data")
                if data:
                    body = base64.urlsafe_b64decode(data).decode("utf-8", errors='ignore')
                    break
    elif "body" in payload and "data" in payload["body"]:
        body = base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8", errors='ignore')
    return body

def fetch_emails_for_date(service, date, skip_keywords, skip_domains):
    email_data = []
    query = f"after:{date.strftime('%Y/%m/%d')} before:{(date + timedelta(days=1)).strftime('%Y/%m/%d')}"
    
    try:
        results = service.users().messages().list(userId="me", q=query).execute()
        messages = results.get("messages", [])
    except Exception as e:
        logging.error(f"Failed to retrieve messages for {date.strftime('%Y-%m-%d')}: {e}")
        return email_data

    total_found = 0
    total_skipped = 0
    total_added = 0

    for msg in messages:
        try:
            msg_details = service.users().messages().get(userId="me", id=msg["id"], format="full").execute()
            payload = msg_details.get("payload", {})
            headers = payload.get("headers", [])
            received_timestamp = int(msg_details.get("internalDate", 0))
            received_date = datetime.fromtimestamp(received_timestamp / 1000).strftime("%Y-%m-%d %H:%M:%S")

            subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
            from_header = next((h["value"] for h in headers if h["name"] == "From"), "Unknown")
            name, company, from_email = extract_name_company_email(from_header)

            body = extract_body(payload)

            if should_skip_email(subject, from_email, skip_keywords, skip_domains):
                logging.info(f"Skipping email from: {from_email}, Subject: {subject}")
                total_skipped += 1
                continue

            email_data.append([
                received_date,
                name,
                company,
                from_email,
                subject,
                body[:49000]
            ])
            total_found += 1

        except Exception as e:
            logging.error(f"Failed to process email ID {msg['id']}: {e}")
            continue

    logging.info(f"Date: {date.strftime('%Y-%m-%d')} - Total emails found: {total_found + total_skipped}, Total emails skipped: {total_skipped}")
    print(f"Date: {date.strftime('%Y-%m-%d')} - Total emails found: {total_found + total_skipped}, Total emails skipped: {total_skipped}")
    
    return email_data, total_found, total_skipped

def write_emails_to_sheets(service, emails, sheet_id, sheet_name="Sheet1"):
    try:
        body = {"values": emails}
        service.spreadsheets().values().append(
            spreadsheetId=sheet_id,
            range=f"{sheet_name}!A1",
            valueInputOption="RAW",
            body=body
        ).execute()
        print(f"Successfully wrote {len(emails)} emails to Google Sheets.")
        logging.info(f"Successfully wrote {len(emails)} emails to Google Sheets.")
        return len(emails)
    except Exception as e:
        print(f"Failed to write emails to Google Sheets: {e}")
        logging.error(f"Failed to write emails to Google Sheets: {e}")
        return 0

def main():
    gmail_service, sheets_service = authenticate_google()

    start_datetime_str = "2024-10-01 00:00:00"
    end_datetime_str = "2024-10-03 23:59:59"
    start_datetime = datetime.strptime(start_datetime_str, "%Y-%m-%d %H:%M:%S")
    end_datetime = datetime.strptime(end_datetime_str, "%Y-%m-%d %H:%M:%S")

    print(f"Processing emails from {start_datetime.strftime('%Y-%m-%d')} to {end_datetime.strftime('%Y-%m-%d')}...")

    skip_keywords = ["upi", "naukri"]
    skip_domains = ["google.com", "dice.com"]

    total_emails_processed = 0
    total_emails_skipped = 0
    total_emails_added = 0

    current_datetime = start_datetime

    while current_datetime <= end_datetime:
        emails, total_found, total_skipped = fetch_emails_for_date(gmail_service, current_datetime, skip_keywords, skip_domains)

        if emails:
            added_emails = write_emails_to_sheets(sheets_service, emails, SHEET_ID, SHEET_NAME)
            total_emails_added += added_emails

        total_emails_processed += total_found
        total_emails_skipped += total_skipped

        current_datetime += timedelta(days=1)

    print(f"Total emails processed: {total_emails_processed + total_emails_skipped}")
    print(f"Total emails skipped: {total_emails_skipped}")
    print(f"Total emails added to Sheets: {total_emails_added}")

    logging.info(f"Total emails processed: {total_emails_processed + total_emails_skipped}")
    logging.info(f"Total emails skipped: {total_emails_skipped}")
    logging.info(f"Total emails added to Sheets: {total_emails_added}")

if __name__ == '__main__':
    main()
