
from django.utils.deprecation import MiddlewareMixin
from .rest_api import api_auth, make_api_response

UNAUTHORIZED = 401

class RestApiAuthMiddleware(MiddlewareMixin):
    
    def process_request(self, request):
        if request.path.startswith("/api") is False:
            return
        if api_auth(request.META) is False:
            return make_api_response(
            {"error": "You are unauthorized to make this request."}, UNAUTHORIZED)