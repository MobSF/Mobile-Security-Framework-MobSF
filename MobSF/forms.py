from django import forms

class UploadFileForm(forms.Form):
    file = forms.FileField()


class FormUtil(object):

    def __init__(self, form):
        self.form = form

    @staticmethod
    def errors_message(form):
        return '; '.join([v for k, v in form.errors.items() for v in v])

    @staticmethod
    def errors(form):
        return form.errors.items()
