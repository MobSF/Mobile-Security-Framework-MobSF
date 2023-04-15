# -*- coding: utf_8 -*-
import hashlib

from django.utils.deprecation import MiddlewareMixin

from mobsf.MobSF.utils import api_key, make_api_response, utcnow
from mobsf.MobSF.views.api import api_static_analysis as api_sz
from mobsf.StaticAnalyzer.models import ApiKeys


def get_api_key(meta):
    """Return supplied API key."""
    if 'HTTP_X_MOBSF_API_KEY' in meta:
        return meta['HTTP_X_MOBSF_API_KEY']
    elif 'HTTP_AUTHORIZATION' in meta:
        return meta['HTTP_AUTHORIZATION']
    return None


class RestApiAuthMiddleware(MiddlewareMixin):
    """Middleware for REST API."""

    readonly_funcs = [api_sz.api_upload, api_sz.api_scan_metadata,
                      api_sz.api_scan, api_sz.api_async_scan,
                      api_sz.api_rescan, api_sz.api_pdf_report,
                      api_sz.api_json_report, api_sz.api_view_source,
                      api_sz.api_recent_scans, api_sz.api_release_scans,
                      api_sz.api_compare, api_sz.api_scorecard,
                      api_sz.api_cyberspect_get_scan,
                      api_sz.api_cyberspect_recent_scans,
                      api_sz.api_cyberspect_completed_scans]

    def process_request(self, request):
        """Handle API authentication."""
        if not request.path.startswith('/api/'):
            return
        if request.method == 'OPTIONS':
            return make_api_response({})
        if not get_api_key(request.META):
            return make_api_response(
                {'error': 'You are unauthorized to make this request.'}, 401)

    def process_view(self, request, view_func, view_args, view_kwargs):
        """Handle API authorization."""
        if not request.path.startswith('/api/'):
            return
        apikey = get_api_key(request.META)
        if apikey == api_key():
            return

        key_hash = hashlib.sha256(apikey.encode('utf-8')).hexdigest()
        db_obj = ApiKeys.objects.filter(KEY_HASH=key_hash,
                                        REVOKED_DATE=None).first()
        if not db_obj:
            return make_api_response(
                {'error': 'API key is invalid or revoked.'}, 403)
        if db_obj.EXPIRE_DATE <= utcnow():
            return make_api_response(
                {'error': 'API key has expired.'}, 403)

        request.META['email'] = db_obj.EMAIL
        role = ApiKeys.Role(db_obj.ROLE)
        if role == ApiKeys.Role.FULL_ACCESS:
            return
        elif role == ApiKeys.Role.READ_ONLY:
            if view_func in self.readonly_funcs:
                return
        elif role == ApiKeys.Role.UPLOAD_ONLY:
            if view_func == api_sz.api_upload:
                return

        return make_api_response({'error': 'Unauthorized request.'}, 403)
