"""Helpers."""
import functools

from django.conf import settings
from django.http import HttpRequest, HttpResponseNotAllowed

ALLOW_METHODS = ['GET', 'POST', 'PUT', 'DELETE',
                 'PATCH', 'OPTIONS', 'HEAD', 'TRACE']


class FileType(object):

    def __init__(self, file_type, file_name_lower):
        self.file_type = file_type
        self.file_name_lower = file_name_lower

    def is_allow_file(self):
        """
        Is File Allowed.

        return bool
        """
        if self.is_apk() or self.is_zip() or self.is_ipa() or self.is_appx():
            return True
        return False

    def is_apk(self):
        return (self.file_type in settings.APK_MIME
                and self.file_name_lower.endswith('.apk'))

    def is_zip(self):
        return (self.file_type in settings.ZIP_MIME
                and self.file_name_lower.endswith('.zip'))

    def is_ipa(self):
        return (self.file_type in settings.IPA_MIME
                and self.file_name_lower.endswith('.ipa'))

    def is_appx(self):
        return (self.file_type in settings.APPX_MIME
                and self.file_name_lower.endswith('.appx'))


def request_method(methods):
    """
    Request Method Checks.

    :param methods http method
    need django HttpRequest
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):

            if (not isinstance(methods, list)
                    and not isinstance(methods, tuple)):
                raise ValueError(
                    'the parameter methods is not a list or tuple')

            methods_upper = [m.upper() for m in methods]
            for method in methods_upper:
                if method not in ALLOW_METHODS:
                    raise ValueError('This method is not allowed')

            request = None
            for arg in args:
                if isinstance(arg, HttpRequest):
                    request = arg
            if request is None:
                raise ValueError('Request object not found')

            if request.method not in methods_upper:
                return HttpResponseNotAllowed(methods_upper)

            return func(*args, **kwargs)
        return wrapper
    return decorator
