import base64
import functools
import json
import logging
import urllib.request
import os

import jwt

from django.core.exceptions import ImproperlyConfigured
from django.conf import settings

logger = logging.getLogger(__name__)
ACCESS_TOKEN_HEADER = 'HTTP_X_AMZN_OIDC_ACCESSTOKEN'
IDENTITY_HEADER = 'HTTP_X_AMZN_OIDC_IDENTITY'
DATA_HEADER = 'HTTP_X_AMZN_OIDC_DATA'


def alb_idp_auth_middleware(
    get_response, force_logout_if_no_header=False, region='us-east-2',
):
    region = os.environ.get('AWS_REGION')
    if hasattr(settings, 'AWS_REGION'):
        region = settings.AWS_REGION
    if not region:
        raise ImproperlyConfigured(
            'requires environment variable AWS_REGION or settings.AWS_REGION.',
        )

    def middleware(request):
        identifier = JWTIdentifier(region=region)
        info = identifier.identify(request)
        if info:
            logger.debug('JWT Claims: %s', info)
            request.META['REMOTE_USER'] = info['email']
            request.META['user_claims'] = info
        return get_response(request)

    return middleware


@functools.lru_cache(maxsize=None)
def get_public_key(region, key_id):
    url = public_key_endpoint(region, key_id)
    with urllib.request.urlopen(url) as res:
        return res.read()


def public_key_endpoint(region, key_id):
    return f'https://public-keys.auth.elb.{region}.amazonaws.com/{key_id}'


def verify(data: str, region: str, kid: str, alg: str) -> dict:
    pubkey = get_public_key(region, kid)
    return jwt.decode(data, pubkey, algorithms=[alg])


def extract_headers(data: str, encoding='utf-8') -> dict:
    try:
        jwt_headers = data.split('.')[0]
        decoded_jwt_headers = base64.b64decode(jwt_headers + '=' * 10)
        decoded_jwt_headers = decoded_jwt_headers.decode(encoding=encoding)
        decoded_json = json.loads(decoded_jwt_headers)
        return decoded_json
    except Exception:
        logger.error('Unable to extract headers from JWT')
        return None


class JWTIdentifier:
    def __init__(self, region: str) -> None:
        self.region = region

    def verify(self, data: str) -> dict:
        jwt_headers = extract_headers(data)
        return verify(data, self.region, jwt_headers['kid'],
                      jwt_headers['alg'])

    def identify(self, request) -> dict:
        if DATA_HEADER not in request.META:
            return
        data = request.META[DATA_HEADER]
        info = self.verify(data)
        return info
