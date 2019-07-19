import re

from django import forms


class AttackDetect(forms.Form):
    file = forms.CharField()

    def clean_file(self):
        """Check ../ from path."""
        file = self.cleaned_data['file']
        if (('../' in file) or ('%2e%2e' in file)
                or ('..' in file) or ('%252e' in file)):
            raise forms.ValidationError('Attack Detected')

        return file


class IOSChecks(forms.Form):
    file = forms.CharField()
    type = forms.ChoiceField(  # noqa A003
        choices=(
            ('ipa', 'ipa'),
            ('ios', 'ios')))

    def clean_ext(self):
        """Safe Extension."""
        file = self.cleaned_data['file']
        ext = file.split('.')[-1]
        ext_type = re.search('plist|db|sqlitedb|sqlite|txt|m', ext)
        if not ext_type:
            raise forms.ValidationError('File Extension not supported')
        return file


class APIChecks(forms.Form):
    hash = forms.CharField(min_length=32, max_length=32)  # noqa A003

    def clean_hash(self):
        """Hash is valid."""
        md5 = self.cleaned_data['hash']
        md5_match = re.match('^[0-9a-f]{32}$', md5)
        if not md5_match:
            raise forms.ValidationError('Invalid Hash')
        return md5


class WebChecks(forms.Form):
    md5 = forms.CharField(min_length=32, max_length=32)

    def clean_hash(self):
        """Hash is valid."""
        md5 = self.cleaned_data['md5']
        md5_match = re.match('^[0-9a-f]{32}$', md5)
        if not md5_match:
            raise forms.ValidationError('Invalid Hash')
        return md5


class AndroidChecks(forms.Form):
    type = forms.ChoiceField(  # noqa A003
        choices=(
            ('eclipse', 'eclipse'),
            ('studio', 'studio'),
            ('apk', 'apk')))

    def clean_ext(self):
        """Safe Extension."""
        file = self.cleaned_data['file']
        ext = file.split('.')[-1]
        ext_type = re.search('java|smali', ext)
        if not ext_type:
            raise forms.ValidationError('File Extension not supported')
        return file


class ViewSourceIOSApiForm(AttackDetect, IOSChecks, APIChecks):
    pass


class ViewSourceIOSForm(AttackDetect, IOSChecks, WebChecks):
    pass


class ViewSourceAndroidApiForm(AttackDetect, AndroidChecks, APIChecks):
    pass


class ViewSourceAndroidForm(AttackDetect, AndroidChecks, WebChecks):
    pass
