from django import forms

class UploadFileForm(forms.Form):
    file = forms.FileField()


class FormUtil(object):

    def __init__(self, form):
        self.form = form

    @staticmethod
    def errors_message(form):
        """
        :param form forms.Form
        form.errors.get_json_data() django 2.0 or higher

        :return
        example { "error": "file This field is required." }
        """
        errors_messages = []
        for k, value in form.errors.get_json_data().items():
            errors_messages.append(
                (k + ' ' + ' , '.join([i['message'] for i in value])))
        return '; '.join(errors_messages)

    @staticmethod
    def errors(form):
        return form.errors.items()
