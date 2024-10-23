import imaplib
import email
from email.header import decode_header
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from datetime import datetime, timedelta
import re
import logging

# IMAP server login credentials
EMAIL = "gadejaganmohan@gmail.com"
PASSWORD = "kscf zrou qtzj ogky"  # Use an app-specific password for security
IMAP_SERVER = "imap.gmail.com"
IMAP_PORT = 993

# Google Sheets API setup
SHEET_ID = "15v2PDEguUqkn88eEwThu5hurzdFIFntfMCyLpTz1Zkc"
SHEET_NAME = "Sheet1"
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]

# Load credentials from the token.json file
creds = Credentials.from_authorized_user_file("token.json", SCOPES)

# Connect to Google Sheets API
service = build("sheets", "v4", credentials=creds)
sheet = service.spreadsheets()

# Set up logging
logging.basicConfig(filename='email_extraction.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Extract email body (plain text) from email message
def extract_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_payload(decode=True).decode(errors='ignore')
    else:
        return msg.get_payload(decode=True).decode(errors='ignore')
    return ""

# Extract sender name, company, and email
def extract_name_company_email(from_header):
    match = re.match(r'^"?(.+?)"?\s*<(.+?)>$', from_header)
    if match:
        name = match.group(1).strip()
        email = match.group(2).strip()
        company = "Unknown"  # Adjust if you need to parse the company
        return name, company, email
    return "Unknown", "Unknown", from_header

# Function to check if email subject or sender is to be skipped
def should_skip_email(subject, from_email, skip_keywords, skip_domains):
    # Check for keywords in subject
    if any(keyword.lower() in subject.lower() for keyword in skip_keywords):
        return True

    # Check for domains in email
    domain = from_email.split('@')[-1].lower()
    if any(domain.endswith(skip_domain) for skip_domain in skip_domains):
        return True

    return False

# Connect to IMAP server and fetch emails for a specific date
def extract_emails_for_date(date):
    imap = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    imap.login(EMAIL, PASSWORD)
    imap.select("inbox")
    
    query = f'ON "{date.strftime("%d-%b-%Y")}"'
    result, data = imap.search(None, query)
    email_ids = data[0].split()
    
    emails = []
    skip_keywords = ["hotlist", "hot list", "available", "bench", "datacamp"]
    skip_domains = ["google.com", "dice.com"]
    total_found = 0
    total_skipped = 0

    for email_id in email_ids:
        result, msg_data = imap.fetch(email_id, "(RFC822)")
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                received_date = email.utils.parsedate_to_datetime(msg.get("Date"))
                subject = decode_header(msg["Subject"])[0][0]
                subject = subject.decode(errors='ignore') if isinstance(subject, bytes) else subject
                from_email = msg.get("From")
                name, company, email_addr = extract_name_company_email(from_email)
                body = extract_body(msg)

                # Check if the email should be skipped
                if should_skip_email(subject, email_addr, skip_keywords, skip_domains):
                    logging.info(f"Skipping email from: {email_addr}, Subject: {subject}")
                    total_skipped += 1
                    continue  # Skip this email

                # Add email data to the list
                emails.append([
                    received_date.strftime("%Y-%m-%d %H:%M:%S"),
                    name,
                    company,
                    email_addr,
                    subject,
                    body[:49000]  # Truncate to avoid exceeding Google Sheets cell limit
                ])
                total_found += 1
    
    imap.logout()
    logging.info(f"Date: {date.strftime('%Y-%m-%d')} - Total emails found: {total_found}, Total emails skipped: {total_skipped}")
    print(f"Date: {date.strftime('%Y-%m-%d')} - Total emails found: {total_found}, Total emails skipped: {total_skipped}")
    
    return emails

# Write emails to Google Sheets
def write_emails_to_sheets(emails):
    try:
        body = {
            "values": emails
        }
        sheet.values().append(
            spreadsheetId=SHEET_ID,
            range=f"{SHEET_NAME}!A1",
            valueInputOption="RAW",
            body=body
        ).execute()
        print(f"Successfully wrote {len(emails)} emails to Google Sheets.")
        logging.info(f"Successfully wrote {len(emails)} emails to Google Sheets.")
    except Exception as e:
        print(f"Failed to write emails to Google Sheets: {e}")
        logging.error(f"Failed to write emails to Google Sheets: {e}")

# Main function to fetch and insert emails into Google Sheets
def main():
    start_datetime_str = "2024-10-01 00:00:00"
    end_datetime_str = "2024-10-05 23:59:59"
    start_datetime = datetime.strptime(start_datetime_str, "%Y-%m-%d %H:%M:%S")
    end_datetime = datetime.strptime(end_datetime_str, "%Y-%m-%d %H:%M:%S")

    print(f"Processing emails from {start_datetime} to {end_datetime}...")

    current_datetime = start_datetime

    while current_datetime <= end_datetime:
        # Extract emails for the current day
        emails = extract_emails_for_date(current_datetime)

        # Write emails to Google Sheets if any are found
        if emails:
            write_emails_to_sheets(emails)

        # Move to the next day
        current_datetime += timedelta(days=1)

    print("Completed processing all days in the range.")

if __name__ == '__main__':
    main()
