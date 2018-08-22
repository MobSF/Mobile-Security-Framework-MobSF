
from django.http import HttpResponse

import json

class ApiResponseData(object):

    def __init__(self, error, data, status):
        self._error = error
        self._data = data
        self._status = status

    @property
    def error(self):
        return self._error

    @error.setter
    def error(self, value):
        self._error = value

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = value

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._status = value




class ApiResponse(object):

    def __init__(self, api_response):
        """
        :param api_response ApiResponse
        """
        self.api_response = api_response

    def make_response(self):
        api_resp = HttpResponse(
            json.dumps(
                self.api_response.data, 
                sort_keys=True,
                indent=4,
                separators=(',', ': ')),
            content_type="application/json; charset=utf-8",
            status=self.api_response.status)
        api_resp['Access-Control-Allow-Origin'] = '*'
        return api_resp

    @staticmethod
    def response(data, status=200):
        """Make API Response"""
        api_resp = HttpResponse(json.dumps(
            data, sort_keys=True,
            indent=4, separators=(',', ': ')), content_type="application/json; charset=utf-8", status=status)
        api_resp['Access-Control-Allow-Origin'] = '*'
        return api_resp
