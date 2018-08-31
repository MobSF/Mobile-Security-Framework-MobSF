"""
REST API Middleware
"""
from django.utils.deprecation import MiddlewareMixin
from MobSF.views.api.rest_api import (
    api_auth,
    make_api_response
)

UNAUTHORIZED = 401


class RestApiAuthMiddleware(MiddlewareMixin):

    def process_request(self, request):
        if not request.path.startswith("/api/"):
            return
        if not api_auth(request.META):
            return make_api_response(
                {"error": "You are unauthorized to make this request."}, UNAUTHORIZED)
