"""File upload to iOS form."""
from django import forms


class AndroidDynamicAnalysisForm(forms.Form):
    """Validate Android dynamic-analysis preparation options."""

    device_mode = forms.ChoiceField(
        required=False,
        choices=(
            ('auto', 'auto'),
            ('rooted', 'rooted'),
            ('gadget', 'gadget'),
        ),
    )
    install = forms.ChoiceField(
        required=False,
        choices=(('0', '0'), ('1', '1')),
    )
    re_install = forms.ChoiceField(
        required=False,
        choices=(('0', '0'), ('1', '1')),
    )


class UploadFileForm(forms.Form):
    file = forms.FileField()
