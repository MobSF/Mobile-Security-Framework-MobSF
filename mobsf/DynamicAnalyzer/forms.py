"""File upload to iOS form."""
from django import forms


class AndroidDeviceSelectionForm(forms.Form):
    """Restrict device selection to connected ADB identifiers."""

    identifier = forms.ChoiceField(choices=())

    def __init__(self, devices, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['identifier'].choices = tuple(
            (device['identifier'], device['identifier'])
            for device in devices
            if device['state'] == 'device'
        )


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
    uninstall_existing = forms.ChoiceField(
        required=False,
        choices=(('0', '0'), ('1', '1')),
    )
    replace_existing_gadget = forms.ChoiceField(
        required=False,
        choices=(('0', '0'), ('1', '1')),
    )


class UploadFileForm(forms.Form):
    file = forms.FileField()
