import boto3
import botocore
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

arrowed_email_str = os.environ.get('ALLOWED_EMAILS').split(',')
ALLOWED_EMAILS = list(map(lambda x: x.strip(), arrowed_email_str))
arrowed_domain_str = os.environ.get('ALLOWED_DOMAINS').split(',')
ALLOWED_DOMAINS = list(map(lambda x: x.strip(), arrowed_domain_str))

def lambda_handler(event, context):
    logger.debug(event)
    
    email = None
    domain = None
    google_username = None

    if event.get('request'):
        if event.get('request').get('userAttributes'):
            email = event.get('request').get('userAttributes').get('email')
            domain = email.split('@')[1]
    
    if not email or not domain:
        logger.info('no email or domain')
        return ''
    
    if event.get('userName'):
        if event.get('userName').startswith('Google_'):
            google_username = event.get('userName')[7:]

    if not google_username:
        logger.info('not google idp')
        return ''

    # check email
    if email in ALLOWED_EMAILS:
        logger.info('email matched {}'.format(email))
        event['response']['autoConfirmUser'] = True
        return event
        
    # check domain
    if domain in ALLOWED_DOMAINS:
        logger.info('domain matched {}'.format(domain))
        event['response']['autoConfirmUser'] = True
        return event

    logger.info('email nor domain does not matched')
    return ''
