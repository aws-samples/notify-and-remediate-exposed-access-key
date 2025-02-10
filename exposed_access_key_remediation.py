import boto3
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
from datetime import datetime, timezone

def get_html_template(content):
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ 
                font-family: Arial, sans-serif; 
                line-height: 1.6; 
                color: #333; 
            }}
            .container {{ 
                max-width: 800px; 
                margin: 0 auto; 
                padding: 20px; 
            }}
            .header {{ 
                background-color: #ff4444; 
                color: white; 
                padding: 20px; 
                text-align: center; 
            }}
            .section {{ 
                margin: 20px 0; 
                padding: 20px; 
                background-color: #f9f9f9; 
                border-radius: 5px; 
            }}
            .success {{ 
                background-color: #e8f5e9; 
                border-left: 5px solid #4caf50; 
                padding: 15px; 
            }}
            table {{ 
                width: 100%; 
                border-collapse: collapse; 
                margin: 10px 0; 
            }}
            th, td {{ 
                padding: 12px; 
                text-align: left; 
                border-bottom: 1px solid #ddd; 
            }}
            th {{ 
                background-color: #f5f5f5; 
            }}
            .footer {{ 
                text-align: center; 
                margin-top: 20px; 
                color: #666; 
            }}
        </style>
    </head>
    <body>
        <div class="container">{content}</div>
    </body>
    </html>
    """

def send_remediation_email(user, access_key_id):
    current_time = datetime.now(timezone.utc)
    
    email_content = f"""
        <div class="header">
            <h1>🛡️ AWS Access Key Automatically Disabled</h1>
        </div>
        
        <div class="section success">
            <h2>Remediation Action Completed</h2>
            <p>An exposed AWS access key has been automatically disabled to prevent unauthorized access.</p>
        </div>
        
        <div class="section">
            <h2>Action Details</h2>
            <table>
                <tr><th>Access Key ID</th><td>{access_key_id}</td></tr>
                <tr><th>IAM User</th><td>{user}</td></tr>
                <tr><th>Action Taken</th><td>Access Key Disabled</td></tr>
                <tr><th>Remediation Time</th><td>{current_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Next Steps</h2>
            <ul>
                <li>Review CloudTrail logs for any unauthorized activity</li>
                <li>Create a new access key if needed</li>
                <li>Update any applications using the old access key</li>
                <li>Consider implementing additional security measures</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>This is an automated security remediation notification.</p>
        </div>
    """

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f"ACTION TAKEN: AWS Access Key {access_key_id} Has Been Disabled"
    msg['From'] = os.environ['SENDER_EMAIL']
    msg['To'] = os.environ['RECIPIENT_EMAIL']
    
    html_part = MIMEText(get_html_template(email_content), 'html')
    msg.attach(html_part)

    ses = boto3.client('ses')
    try:
        response = ses.send_raw_email(
            Source=os.environ['SENDER_EMAIL'],
            Destinations=[os.environ['RECIPIENT_EMAIL']],
            RawMessage={'Data': msg.as_string()}
        )
        return True
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        return False

def lambda_handler(event, context):
    try:
        detail = event.get('detail', {})
        user_arn = detail['affectedEntities'][0].get('entityValue', 'N/A')
        access_key_id = detail['affectedEntities'][0]['tags']['accessKeyId']
        user=user_arn.split('user/')[-1]
        
        if not access_key_id.isalnum():
            raise ValueError("Access key ID must contain only alphanumeric characters")
            
        iam = boto3.client('iam')
        response = iam.update_access_key(
            UserName=user,
            AccessKeyId=access_key_id,
            Status='Inactive'
        )
        
        # Send email notification about the remediation
        email_sent = send_remediation_email(user, access_key_id)
        
        return {
            'statusCode': 200,
            'body': {
                'message': 'Access key successfully disabled',
                'user': user,
                'keyId': access_key_id,
                'status': 'INACTIVE',
                'emailSent': email_sent
            }
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'Failed to disable access key'
            }
        }
