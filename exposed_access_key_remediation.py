import json
import boto3
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os

def get_html_template(content):
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 800px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: #ff4444; color: white; padding: 20px; text-align: center; }}
            .section {{ margin: 20px 0; padding: 20px; background-color: #f9f9f9; border-radius: 5px; }}
            .success {{ background-color: #e8f5e9; border-left: 5px solid #4caf50; padding: 15px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f5f5f5; }}
            .footer {{ text-align: center; margin-top: 20px; color: #666; }}
        </style>
    </head>
    <body>
        <div class="container">{content}</div>
    </body>
    </html>
    """

def attach_deny_all_policy(username):
    """Attach a deny all policy to the compromised user"""
    try:
        iam = boto3.client('iam')
        
        deny_all_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        
        policy_name = f"DenyAll-Compromised-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        
        response = iam.put_user_policy(
            UserName=username,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(deny_all_policy)
        )
        
        return True, f"Successfully attached deny all policy: {policy_name}"
    except Exception as e:
        return False, f"Failed to attach deny all policy: {str(e)}"

def send_remediation_email(username, access_key_id, policy_attached, policy_message):
    """Send email notification about remediation actions"""
    current_time = datetime.now(timezone.utc)
    
    email_content = f"""
        <div class="header">
            <h1>🛡️ AWS Access Key Automatically Disabled</h1>
        </div>
        
        <div class="section success">
            <h2>Remediation Actions Completed</h2>
            <p>An exposed AWS access key has been automatically disabled and additional security measures have been implemented.</p>
        </div>
        
        <div class="section">
            <h2>Action Details</h2>
            <table>
                <tr><th>Access Key ID</th><td>{access_key_id}</td></tr>
                <tr><th>IAM User</th><td>{username}</td></tr>
                <tr><th>Access Key Status</th><td>INACTIVE</td></tr>
                <tr><th>Deny Policy Status</th><td>{"✓ Applied" if policy_attached else "❌ Failed"}</td></tr>
                <tr><th>Remediation Time</th><td>{current_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Next Steps</h2>
            <ul>
                <li>Review CloudTrail logs for any unauthorized activity</li>
                <li>Create a new access key if needed</li>
                <li>Update any applications using the old access key</li>
                <li>Review and update security policies</li>
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
        access_key_id = detail['eventMetadata']['publicKey'].strip()
        username = detail['eventMetadata'].get('userName', 'N/A')
        
        # Disable access key
        iam = boto3.client('iam')
        iam.update_access_key(
            UserName=username,
            AccessKeyId=access_key_id,
            Status='Inactive'
        )
        
        # Attach deny all policy
        policy_attached, policy_message = attach_deny_all_policy(username)
        
        # Send email notification
        email_sent = send_remediation_email(username, access_key_id, policy_attached, policy_message)
        
        return {
            'statusCode': 200,
            'body': {
                'message': 'Remediation actions completed',
                'user': username,
                'keyId': access_key_id,
                'keyStatus': 'INACTIVE',
                'policyAttached': policy_attached,
                'emailSent': email_sent
            }
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': {
                'error': str(e),
                'message': 'Failed to complete remediation actions'
            }
        }
