import json
import os
import sys
import logging
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ALERT_ROLES = os.environ['ALERT_ROLES'].replace(' ', '').split(',')

logger = logging.getLogger()
logging.basicConfig()
logger.setLevel('INFO')

def post_to_webhook(message, webhook_url=os.environ['WEBHOOK_URL']):
    req = Request(webhook_url, json.dumps(message).encode())
    try:
        response = urlopen(req)
        response.read()
        logger.info("message posted to webhook")

    except HTTPError as e:
        logger.error("request failed: %d %s", e.code, e.reason)
        raise Exception('webhook request failed')

    except URLError as e:
        logger.error("server connection failed: %s", e.reason)
        raise Exception('server connection failed')


def lambda_handler(event=None, context=None):
    logger.info(json.dumps(event))
    type_ = event['detail-type']
    assert type_.casefold() == 'aws console sign in via cloudtrail', f"Unknown detail-type {type_}"

    detail = event['detail']
    eventName = detail['eventName']
    if eventName.casefold() != 'switchrole':
        logger.info(f"Skipping eventName {eventName}")
        return

    user_identity = detail['userIdentity']
    identity_type = user_identity['type']
    if identity_type.casefold() != 'assumedrole':
        logger.info(f"Skipping userIdentity type {identity_type}")
        return

    role, user = user_identity['arn'].split('/')[1:]
    text = f"user: {user}, assumed role: {role}"
    logger.info(text)

    if role in ALERT_ROLES:
        logger.info("sending alert notification")
        message_body = {
          'message': text
        }
        post_to_webhook(message_body)
    else:
      logger.info(f"role: {role} not in ALERT_ROLES")
