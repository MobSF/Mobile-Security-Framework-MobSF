"""File upload to iOS form."""
from django import forms

from mobsf.MobSF.utils import valid_android_device_identifier


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

    identifier = forms.CharField(required=False, max_length=255)
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

    def clean_identifier(self):
        """Validate an optional page-bound Android identifier."""
        identifier = self.cleaned_data['identifier']
        if (identifier
                and not valid_android_device_identifier(identifier)):
            raise forms.ValidationError('Invalid Android device identifier')
        return identifier


class UploadFileForm(forms.Form):
    file = forms.FileField()
