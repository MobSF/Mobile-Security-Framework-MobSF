from django import forms

class UploadFileForm(forms.Form):
    file = forms.FileField()

class ViewSourceForm(forms.Form):
    file = forms.CharField()
    md5 = forms.CharField(min_length=32, max_length=32)
    type = forms.ChoiceField(
        choices=(
            ('eclipse', 'eclipse'),
            ('studio', 'studio'), 
            ('apk', 'apk')
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
