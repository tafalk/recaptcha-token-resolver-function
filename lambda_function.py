"""Recaptcha Resolver"""
import os
import logging
import urllib.parse
import requests
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """Default Handler"""
    logger.info('fetching locations triggered with event %s', event)
    result = {}
    try:
        # Get arguments
        token = event.get('token')
        ip = event.get('ip')

        # Get environment variables
        ssm = boto3.client('ssm')
        secret = ssm.get_parameter(
            Name=os.environ['RECAPTCHA_SECRET_NAME'], WithDecryption=False)
        endpoint = os.environ['RECAPTCHA_VERIFY_ENDPOINT']

        # Prepare URL and query string
        params = {'secret': secret, 'response': token}
        if ip is not None:
            params['remoteip'] = ip
        req_url = endpoint + '?' + urllib.parse.urlencode(params)

        # Make the REST call
        resp = requests.get(req_url, timeout=3)
        resp.raise_for_status()

        # Parse result
        init_result = resp.json()
        result = {
            'success': init_result.get('success'),
            'challengeTimestamp': init_result.get('challenge_ts'),
            'hostname': init_result.get('hostname'),
            'errorCodes': init_result.get('error-codes')
        }
        logger.info(result)
    except requests.exceptions.HTTPError as errh:
        logger.exception('Http Error: %s', errh)
    except requests.exceptions.ConnectionError as errc:
        logger.exception('Error Connecting: %s', errc)
    except requests.exceptions.Timeout as errt:
        logger.exception('Timeout Error: %s', errt)
    except requests.exceptions.RequestException as errr:
        logger.exception('Unexpected Request Error: %s', errr)
    except Exception as e:
        logger.exception('validating tokens failed %s', e)

    return result
