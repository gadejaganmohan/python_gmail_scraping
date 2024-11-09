from datetime import datetime, timedelta
import logging
import base64
import re
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError

# Define API scopes for Gmail and Sheets
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/spreadsheets']

# Google Sheets ID and range for appending data
SPREADSHEET_ID = 'SHEET_ID'
RANGE_NAME = 'SHEET_NAME'  # Adjust according to your sheet setup

# Define keywords and domains to skip
skip_keywords = ["hotlist", "hot list", "available", "bench"]
skip_domains = ["google.com", "dice.com"]

# Initialize logging
logging.basicConfig(filename='email_extraction.log', level=logging.INFO,
                    format='%(asctime)s - %(message)s')

def build_gmail_service():
    creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    return build('gmail', 'v1', credentials=creds)

def build_sheets_service():
    creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    return build('sheets', 'v4', credentials=creds)

def search_emails(service, start_datetime, end_datetime):
    start_timestamp = int(start_datetime.timestamp())
    end_timestamp = int(end_datetime.timestamp())
    query = f"after:{start_timestamp} before:{end_timestamp}"
    results = service.users().messages().list(userId='me', q=query).execute()
    messages = results.get('messages', [])
    return messages

def parse_from_field(from_field):
    # Extract email and name from "From" field
    match = re.match(r'(?:"?([^"]*)"?\s)?(?:<?([^@]+)@([^\s>]+)>?)', from_field)
    if match:
        name = match.group(1) or ""
        email = f"{match.group(2)}@{match.group(3)}"
        company = match.group(3).split('.')[0]  # Extract company from domain part of email
        return name, company, email
    return "", "", from_field

def get_email_body(msg):
    # Extract body content
    parts = msg['payload'].get('parts', [])
    for part in parts:
        if part['mimeType'] == 'text/plain':
            return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
    return ''

def process_emails(service, messages):
    email_data = []
    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        headers = msg['payload']['headers']

        # Extract details
        date = next((header['value'] for header in headers if header['name'] == 'Date'), None)
        from_field = next((header['value'] for header in headers if header['name'] == 'From'), None)
        subject = next((header['value'] for header in headers if header['name'] == 'Subject'), None)
        body = get_email_body(msg)

        # Parse name, company, and email from "From" field
        name, company, email = parse_from_field(from_field)

        # Skip based on subject keywords or email domains
        if any(keyword.lower() in subject.lower() for keyword in skip_keywords):
            #logging.info(f"Skipping email with subject containing a skip keyword: {subject}")
            continue
        if any(domain in email for domain in skip_domains):
            #logging.info(f"Skipping email from domain in skip list: {email}")
            continue

        # Append only required details
        email_data.append([date, name, company, email, subject, body])
        #logging.info(f"Processed email - Date: {date}, Email: {email}")
    
    return email_data

def append_to_google_sheets(sheets_service, email_data):
    body = {
        'values': email_data
    }
    try:
        sheets_service.spreadsheets().values().append(
            spreadsheetId=SPREADSHEET_ID,
            range=RANGE_NAME,
            valueInputOption="RAW",
            body=body
        ).execute()
        logging.info(f"Successfully appended {len(email_data)} rows to Google Sheets.")
        print(f"Successfully appended {len(email_data)} rows to Google Sheets.")
    except HttpError as error:
        logging.error(f"An error occurred while appending data to Google Sheets: {error}")

def main():
    # Initialize Gmail and Sheets API services
    gmail_service = build_gmail_service()
    sheets_service = build_sheets_service()

    # Define start and end dates for email extraction
    start_date_str = "2024-06-01"
    end_date_str = "2024-06-10"
    
    start_of_day = datetime.strptime(start_date_str, "%Y-%m-%d")
    end_of_day = datetime.strptime(end_date_str, "%Y-%m-%d") + timedelta(days=1)

    # Loop through each 30-minute interval
    current_start = start_of_day
    while current_start < end_of_day:
        current_end = current_start + timedelta(minutes=30)
        logging.info(f"Searching emails from {current_start.strftime('%Y-%m-%d %H:%M:%S')} to {current_end.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Searching emails from {current_start.strftime('%Y-%m-%d %H:%M:%S')} to {current_end.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Search and process emails
        messages = search_emails(gmail_service, current_start, current_end)
        if messages:
            email_data = process_emails(gmail_service, messages)
            #logging.info(f"Found {len(email_data)} emails in interval {current_start.strftime('%Y-%m-%d %H:%M')} to {current_end.strftime('%Y-%m-%d %H:%M')}")
            
            # Append email data to Google Sheets if there is data
            if email_data:
                append_to_google_sheets(sheets_service, email_data)
        else:
            logging.info(f"No emails found in interval {current_start.strftime('%Y-%m-%d %H:%M')} to {current_end.strftime('%Y-%m-%d %H:%M')}")

        # Move to the next 30-minute interval
        current_start = current_end

if __name__ == '__main__':
    main()
