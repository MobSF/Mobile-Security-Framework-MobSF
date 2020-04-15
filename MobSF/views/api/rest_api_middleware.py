# -*- coding: utf_8 -*-
"""REST API Middleware."""
from django.utils.deprecation import MiddlewareMixin

from MobSF.views.api.rest_api import api_auth, make_api_response


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
