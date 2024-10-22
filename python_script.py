import imaplib
import email
from email.header import decode_header
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from datetime import datetime
import re
import logging

# Set up logging
logging.basicConfig(filename='email_extraction.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
console_handler = logging.StreamHandler()  # Create a console handler
console_handler.setLevel(logging.INFO)  # Set the level to INFO
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)

logging.getLogger().addHandler(console_handler)  # Add the console handler to the logger

# IMAP server login credentials
EMAIL = "gadejaganmohan@gmail.com"
PASSWORD = "YOUR IMAP PASSWORD"  # Use an app-specific password for security
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

# Define keywords and domains to skip
SKIP_KEYWORDS = ["hotlist", "hot list", "available", "bench"]
SKIP_DOMAINS = ["google.com", "dice.com"]

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
        company = "Unknown"  # You can further process 'name' to extract a company name if needed
        return name, company, email
    return "Unknown", "Unknown", from_header

# Connect to IMAP server and fetch emails by date range
def extract_emails_by_datetime_range(start_datetime, end_datetime):
    imap = imaplib.IMAP4_SSL(IMAP_SERVER, IMAP_PORT)
    imap.login(EMAIL, PASSWORD)
    imap.select("inbox")
    
    query = f'SINCE "{start_datetime.strftime("%d-%b-%Y")}" BEFORE "{end_datetime.strftime("%d-%b-%Y")}"'
    result, data = imap.search(None, query)
    email_ids = data[0].split()
    
    emails = []
    skipped_count = 0
    
    total_found = len(email_ids)
    logging.info(f"Total emails found in the specified range: {total_found}")  # Log total emails found
    
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

                # Check for skipped keywords
                if any(keyword.lower() in subject.lower() for keyword in SKIP_KEYWORDS):
                    logging.info(f"Skipping email due to keyword in subject: {subject}")
                    skipped_count += 1
                    continue

                # Check for skipped domains
                domain = email_addr.split('@')[-1]
                if any(domain.endswith(skip_domain) for skip_domain in SKIP_DOMAINS):
                    logging.info(f"Skipping email from domain: {domain}")
                    skipped_count += 1
                    continue

                # Add email data to the list
                emails.append([
                    received_date.strftime("%Y-%m-%d %H:%M:%S"),
                    name,
                    company,
                    email_addr,
                    subject,
                    body[:49000]  # Truncate to avoid exceeding Google Sheets cell limit
                ])
    
    imap.logout()
    
    total_added = len(emails)
    logging.info(f"Total emails added to Google Sheets: {total_added}")  # Log total emails added
    logging.info(f"Total emails skipped: {skipped_count}")  # Log total skipped emails
    
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
        logging.info(f"Successfully wrote {len(emails)} emails to Google Sheets.")
    except Exception as e:
        logging.error(f"Failed to write emails to Google Sheets: {e}")

# Main function to fetch and insert emails into Google Sheets
def main():
    start_datetime_str = "2024-10-01 00:00:00"
    end_datetime_str = "2024-10-02 23:59:59"
    start_datetime = datetime.strptime(start_datetime_str, "%Y-%m-%d %H:%M:%S")
    end_datetime = datetime.strptime(end_datetime_str, "%Y-%m-%d %H:%M:%S")

    logging.info(f"Processing emails from {start_datetime} to {end_datetime}...")

    # Extract emails in the date range
    emails = extract_emails_by_datetime_range(start_datetime, end_datetime)

    # Write emails to Google Sheets
    if emails:
        write_emails_to_sheets(emails)
    else:
        logging.info("No emails found in the specified range.")

if __name__ == '__main__':
    main()
