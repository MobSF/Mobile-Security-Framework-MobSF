import re

from django import forms


class UploadFileForm(forms.Form):
    file = forms.FileField()


class BaseViewSourceForm(forms.Form):
    md5 = forms.CharField(min_length=32, max_length=32)
    file = forms.CharField()

    def clean_file(self):
        """
        Check ../ from path
        """
        file = self.cleaned_data['file']
        if (("../" in file) or ("%2e%2e" in file) or 
            (".." in file) or ("%252e" in file)):
            raise forms.ValidationError("path error")

        return file

    def clean_md5(self):
        """
        """
        md5 = self.cleaned_data['md5']
        md5_match = re.match('^[0-9a-f]{32}$', md5)
        if not md5_match:
            raise forms.ValidationError("md5 format error")
        return md5
        


class ViewSourceAndroidForm(BaseViewSourceForm):
    type = forms.ChoiceField(
        choices=(
            ('eclipse', 'eclipse'),
            ('studio', 'studio'), 
            ('apk', 'apk')
        )
    )

class ViewSourceIosForm(BaseViewSourceForm):
    mode = forms.ChoiceField(
        choices=(
            ('ipa', 'ipa'),
            ('ios', 'ios')
        )
    )
    type = forms.ChoiceField(
        choices=(
            ('m', 'm'),
            ('xml', 'xml'),
            ('db', 'db'),
            ('txt', 'txt')
        )
    )

class FormUtil(object):

    def __init__(self, form):
        self.form = form

    @staticmethod
    def errors_message(form):
        """
        :param form forms.Form
        form.errors.get_json_data() django 2.0 or higher

        :return
        example
        {
        "error": {
            "file": "This field is required.", 
            "test": "This field is required."
            }
        }
        """
        data = form.errors.get_json_data()
        for k, v in data.items():
            data[k] = ' '.join([value_detail['message'] for value_detail in v])
        return data

    @staticmethod
    def errors(form):
        return form.errors.get_json_data()
