# -*- coding: utf_8 -*-
"""REST API Middleware."""
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin

from mobsf.MobSF.utils import api_key

OK = 200


def make_api_response(data, status=OK):
    """Make API Response."""
    resp = JsonResponse(
        data=data,  # lgtm [py/stack-trace-exposure]
        status=status)
    resp['Access-Control-Allow-Origin'] = '*'
    resp['Access-Control-Allow-Methods'] = 'POST'
    resp['Access-Control-Allow-Headers'] = 'Authorization, X-Mobsf-Api-Key'
    resp['Content-Type'] = 'application/json; charset=utf-8'
    return resp


def api_auth(meta):
    """Check if API Key Matches."""
    if 'HTTP_X_MOBSF_API_KEY' in meta:
        return bool(api_key() == meta['HTTP_X_MOBSF_API_KEY'])
    elif 'HTTP_AUTHORIZATION' in meta:
        return bool(api_key() == meta['HTTP_AUTHORIZATION'])
    return False


class RestApiAuthMiddleware(MiddlewareMixin):
    """
    Middleware.

    Middleware for REST API.
    """

    def process_request(self, request):
        """Middleware to handle API Auth."""
        if not request.path.startswith('/api/'):
            return
        if request.method == 'OPTIONS':
            return make_api_response({}, 200)
        if not api_auth(request.META):
            return make_api_response(
                {'error': 'You are unauthorized to make this request.'}, 401)
