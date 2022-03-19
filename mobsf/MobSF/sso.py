# -*- coding: utf_8 -*-
"""Support for SSO using AWS ALB and Azure AD."""
import base64
import json

import jwt

import logging

import requests

logger = logging.getLogger(__name__)


def parse_jwt(request):
    request.jwt_claims = '{}'
    request.jwt_user = 'unknown'

    if 'x-amzn-oidc-data' not in request.headers:
        return

    # Step 1: Get the key id from JWT headers (the kid field)
    encoded_jwt = request.headers['x-amzn-oidc-data']
    try:
        jwt_headers = encoded_jwt.split('.')[0]
        decoded_jwt_headers = base64.b64decode(jwt_headers)
        decoded_jwt_headers = decoded_jwt_headers.decode('utf-8')
        decoded_json = json.loads(decoded_jwt_headers)
        kid = decoded_json['kid']
    except Exception:
        logger.exception('Error parsing JWT: %s', encoded_jwt)
        return

    # Step 2: Get the public key from regional endpoint
    try:
        url = 'https://public-keys.auth.elb.us-east-2.amazonaws.com/' + kid
        req = requests.get(url)
        pub_key = req.text
    except Exception:
        logger.exception('Error retrieving AWS public key: %s', kid)
        return

    # Step 3: Get the payload
    try:
        payload = jwt.decode(encoded_jwt, pub_key, algorithms=['ES256'])
    except Exception:
        logger.exception('Error decoding JWT: %s', encoded_jwt)
        return

    logger.info('JWT payload: %s', payload)
    logger.info('JWT user: %s', request.headers['x-amzn-oidc-identity'])
    request.jwt_claims = payload
    request.jwt_user = request.headers['x-amzn-oidc-identity']
    return


def is_admin(request):
    return False
