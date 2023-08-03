import os
current_script_path = os.path.abspath (__file__)

# Get the directory containing the current script
current_script_directory = os.path.dirname ( current_script_path )
print ( current_script_directory + "current script" )
# Get the base path of the project
resources = os.path.join ( current_script_directory, "resources" )
print ( resources )
credentials_file = f"{resources}/json_project.json"


import os
import json
# pip install google-auth
#pip install google-auth-oauthlib
# pip install google-api-python-client
from google.oauth2 import credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from email.mime.text import MIMEText
import base64

class GmailSender:
    def __init__(self, secret_file):
        self.CLIENT_SECRET_FILE = secret_file
        self.API_SERVICE_NAME = 'gmail'
        self.API_VERSION = 'v1'
        self.SCOPES = ['https://www.googleapis.com/auth/gmail.compose']
        self.credentials = None

    def authenticate(self):
        flow = InstalledAppFlow.from_client_secrets_file(self.CLIENT_SECRET_FILE, self.SCOPES)
        self.credentials = flow.run_local_server(port=0)

        # Save credentials to token.json
        with open('token.json', 'w') as token_file:
            token_file.write(self.credentials.to_json())

        return self.credentials

    def load_credentials(self):
        if os.path.exists('token.json'):
            with open('token.json', 'r') as token_file:
                credentials_data = token_file.read()
                return credentials.Credentials.from_authorized_user_info(json.loads(credentials_data))
        else:
            return None

    def send_email(self, to_email_id, from_email_id, message_content, mail_subject):
        # Load credentials
        self.credentials = self.load_credentials()

        if self.credentials is None or self.credentials.expired:
            self.credentials = self.authenticate()

        # Create the Gmail service
        gmail_service = build(self.API_SERVICE_NAME, self.API_VERSION, credentials=self.credentials)

        # Create the message
        message = MIMEText(message_content)
        message['to'] = to_email_id
        message['from'] = from_email_id
        message['subject'] = mail_subject

        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
        body = {'raw': raw_message}

        # Send the email
        try:
            message = gmail_service.users().messages().send(
                userId='me',
                body=body
            ).execute()
            return 'Email sent successfully!'
        except Exception as e:
            return str(e)


# obj=GmailSender(credentials_file)
# obj.send_email(to_email_id='johny.achkar01@gmail.com',from_email_id='johny.achkar02@gmail.com',message_content='test',mail_subject="change password")