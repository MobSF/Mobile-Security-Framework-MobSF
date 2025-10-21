from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm


class UploadFileForm(forms.Form):
    file = forms.FileField()


class FormUtil(object):

    def __init__(self, form):
        self.form = form

    @staticmethod
    def errors_message(form):
        """Form Errors.

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


class RegisterForm(UserCreationForm):

    role = forms.ChoiceField(
        choices=(('viewer', 'Viewer'), ('maintainer', 'Maintainer')),
        required=True,
        help_text='User Role')

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('Email already exists')
        return email

    class Meta:
        """Meta Class."""

        model = User
        fields = ['username', 'password1', 'password2', 'email', 'role']
