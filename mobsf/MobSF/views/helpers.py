"""Helpers."""
import functools

from mobsf.MobSF.utils import (
    is_a_magic,
    is_dylib_magic,
    is_elf_so_magic,
    is_zip_magic,
)

from django.conf import settings
from django.http import HttpRequest, HttpResponseNotAllowed

ALLOW_METHODS = ['GET', 'POST', 'PUT', 'DELETE',
                 'PATCH', 'OPTIONS', 'HEAD', 'TRACE']


class FileType(object):

    def __init__(self, file_obj):
        self.file_type = file_obj.content_type
        self.file_name_lower = file_obj.name.lower()
        self.zip = is_zip_magic(file_obj)
        self.so = is_elf_so_magic(file_obj)
        self.dylib = is_dylib_magic(file_obj)
        self.a = is_a_magic(file_obj)

    def is_allow_file(self):
        """
        Is File Allowed.

        return bool
        """
        if self.so and self.is_so():
            return True
        if self.dylib and self.is_dylib():
            return True
        if self.a and self.is_a():
            return True
        if self.zip and (
            self.is_apk()
                or self.is_xapk()
                or self.is_zip()
                or self.is_ipa()
                or self.is_appx()
                or self.is_apks()
                or self.is_aab()
                or self.is_jar()
                or self.is_aar()):
            return True
        return False

    def is_apks(self):
        return (self.file_type in settings.APK_MIME
                and self.file_name_lower.endswith('.apks'))

    def is_xapk(self):
        return (self.file_type in settings.APK_MIME
                and self.file_name_lower.endswith('.xapk'))

    def is_aab(self):
        return (self.file_type in settings.APK_MIME
                and self.file_name_lower.endswith('.aab'))

    def is_apk(self):
        return (self.file_type in settings.APK_MIME
                and self.file_name_lower.endswith('.apk'))

    def is_jar(self):
        return (self.file_type in settings.APK_MIME
                and self.file_name_lower.endswith('.jar'))

    def is_aar(self):
        return (self.file_type in settings.APK_MIME
                and self.file_name_lower.endswith('.aar'))

    def is_so(self):
        return (self.file_type in settings.APK_MIME
                and self.file_name_lower.endswith('.so'))

    def is_dylib(self):
        return (self.file_type in settings.IPA_MIME
                and self.file_name_lower.endswith('.dylib'))

    def is_a(self):
        return (self.file_type in settings.IPA_MIME
                and self.file_name_lower.endswith('.a'))

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
