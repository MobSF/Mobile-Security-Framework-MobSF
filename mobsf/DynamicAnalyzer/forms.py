"""File upload to iOS form."""
from django import forms


class UploadFileForm(forms.Form):
    file = forms.FileField()
