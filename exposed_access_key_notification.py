import json
import boto3
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from collections import defaultdict
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
            .critical {{ background-color: #fff3f3; border-left: 5px solid #ff4444; padding: 15px; }}
            .warning {{ background-color: #fff8e1; border-left: 5px solid #ffc107; padding: 15px; }}
            table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #f5f5f5; }}
            .footer {{ text-align: center; margin-top: 20px; color: #666; }}
            .recommendation-item {{ 
                margin-bottom: 15px; 
                padding: 15px; 
                background-color: #f8f9fa; 
                border-radius: 4px;
                border-left: 3px solid #2196f3;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }}
            .recommendations {{ 
                background-color: #e3f2fd; 
                border-left: 5px solid #2196f3; 
                padding: 20px;
                margin-top: 20px;
            }}
            .recommendations h2 {{
                color: #1565c0;
                margin-bottom: 20px;
            }}

        </style>
    </head>
    <body>
        <div class="container">{content}</div>
    </body>
    </html>
    """
def analyze_cloudtrail_events(access_key_id, start_time=None):
    """Analyze CloudTrail events across all active regions"""
    results = {
        'api_counts': defaultdict(lambda: defaultdict(int)),
        'total_events': 0,
        'errors': []
    }

    # Get all active regions
    ec2 = boto3.client('ec2')
    regions = [region['RegionName'] for region in ec2.describe_regions()['Regions']]
    regions.append('us-east-1')  # Ensure IAM events are captured
    print (regions)
    if not start_time:
        start_time = datetime.now(timezone.utc) - timedelta(days=7)
        print(start_time)
    for region in set(regions):
        try:
            cloudtrail = boto3.client('cloudtrail',region_name=region)
            paginator = cloudtrail.get_paginator('lookup_events')
            
            for page in paginator.paginate(
                LookupAttributes=[{
                    'AttributeKey': 'AccessKeyId',
                    'AttributeValue': access_key_id
                }],
                StartTime=start_time
            ):
                for event in page.get('Events', []):
                    event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                    api_name = event_data.get('eventName', 'Unknown')
                    results['api_counts'][region][api_name] += 1
                    results['total_events'] += 1
        
        except Exception as e:
            results['errors'].append(f"Region {region} error: {str(e)}")

    return results

def get_security_recommendations(bedrock_client, incident_details):
    try:
        response = bedrock_client.invoke_model(
            modelId='anthropic.claude-3-sonnet-20240229-v1:0',
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 500,
                "messages": [{
                    "role": "user",
                    "content": f"""Based on this AWS security incident, provide numbered security recommendations:
                    Incident Details: {incident_details}
                    
                    Format each recommendation on a new line with a number prefix like:
                    1. First recommendation
                    2. Second recommendation
                    
                    Focus on immediate actions and long-term preventive measures.
                    Provide 5-7 specific, actionable recommendations."""
                }],
                "temperature": 0
            })
        )
        recommendations = json.loads(response.get('body').read())['content'][0]['text']
        # Format recommendations as HTML list items
        formatted_recommendations = ""
        for line in recommendations.split('\n'):
            if line.strip():  # Check if line is not empty
                formatted_recommendations += f'<div class="recommendation-item">{line}</div>\n'
        return formatted_recommendations
    except Exception as e:
        return f"Error generating recommendations: {str(e)}"


def lambda_handler(event, context):
    health_event = event.get('event', {})
    detail = health_event.get('detail', {})
    user = detail['affectedEntities'][0].get('entityValue', 'N/A')
    access_key_id = detail['affectedEntities'][0]['tags']['accessKeyId']
    
    event_summary = analyze_cloudtrail_events(access_key_id)

    # Initialize Bedrock client for Claude 3 Sonnet
    bedrock = boto3.client('bedrock-runtime')
    
    # Prepare incident summary with regional data
    incident_summary = f"""
    Access Key Exposure Detected!
    Key ID: {access_key_id}
    User: {user}
    """
    
    try:
        response = bedrock.invoke_model(
            modelId='anthropic.claude-3-sonnet-20240229-v1:0',
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 300,
                "messages": [{
                    "role": "user",
                    "content": f"Summarize this security incident and its impact in a concise way.\n{incident_summary}"
                }],
                "temperature": 0.1
            })
        )
        ai_summary = json.loads(response.get('body').read())['content'][0]['text']
    except Exception as e:
        ai_summary = f"Error generating summary: {str(e)}"

    # Get security recommendations
    security_recommendations = get_security_recommendations(bedrock, incident_summary)

    # Update email content to include regional analysis
    current_time = datetime.now(timezone.utc)
    email_content = f"""
        <div class="header">
            <h1>⚠️ SECURITY ALERT: AWS Access Key Exposure</h1>
        </div>
        
        <div class="section critical">
            <h2>Incident Summary</h2>
            <p>{ai_summary}</p>
        </div>
        
        <div class="section">
            <h2>Exposure Details</h2>
            <table>
                <tr><th>Access Key ID</th><td>{access_key_id}</td></tr>
                <tr><th>Affected User</th><td>{user}</td></tr>
                <tr><th>Detection Time</th><td>{current_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>Last 7 Days API Activity Analysis</h2>
            <table>
                <tr><th>Region</th><th>API Name</th><th>Count</th></tr>
    """
    
    for region, apis in event_summary['api_counts'].items():
        for api_name, count in apis.items():
            email_content += f"""
                <tr>
                    <td>{region}</td>
                    <td>{api_name}</td>
                    <td>{count}</td>
                </tr>
            """
    
    email_content += """
            </table>
        </div>
    """

    # Add Security Recommendations section
    email_content += f"""
    <div class="section recommendations">
        <h2>🛡️ Security Recommendations</h2>
        {security_recommendations}
    </div>
    
    <div class="footer">
        <p>This is an automated security alert. Please take immediate action.</p>
    </div>
"""

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f"URGENT: AWS Access Key Exposure Detected - {access_key_id}"
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
        return {
            'statusCode': 200,
            'body': json.dumps('Email sent successfully')
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps(f'Error sending email: {str(e)}')
        }
