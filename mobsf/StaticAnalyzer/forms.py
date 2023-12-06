import re
from pathlib import Path

from django import forms

from mobsf.MobSF.utils import is_md5


class AttackDetect(forms.Form):
    file = forms.CharField()

    def clean_file(self):
        """Check ../ from path."""
        file = self.cleaned_data['file']
        if (('../' in file) or ('%2e%2e' in file)
                or ('..' in file) or ('%252e' in file)):
            raise forms.ValidationError('Attack Detected')
        # Allowed File extensions
        supported_ext = (r'^\.(kt|java|smali|xml|'
                         r'plist|m|swift|'
                         r'db|sqlitedb|sqlite|txt|json)$')
        if not re.search(supported_ext, Path(file).suffix):
            raise forms.ValidationError('File Extension not supported')
        return file


class IOSChecks(forms.Form):
    type = forms.ChoiceField(  # noqa A003
        choices=(
            ('ipa', 'ipa'),
            ('dylib', 'dylib'),
            ('ios', 'ios')))


class APIChecks(forms.Form):
    hash = forms.CharField(min_length=32, max_length=32)  # noqa A003

    def clean_hash(self):
        """Hash is valid."""
        md5 = self.cleaned_data['hash']
        if not is_md5(md5):
            raise forms.ValidationError('Invalid Hash')
        return md5


class WebChecks(forms.Form):
    md5 = forms.CharField(min_length=32, max_length=32)

    def clean_md5(self):
        """Hash is valid."""
        md5 = self.cleaned_data['md5']
        if not is_md5(md5):
            raise forms.ValidationError('Invalid Hash')
        return md5


class AndroidChecks(forms.Form):
    type = forms.ChoiceField(  # noqa A003
        choices=(
            ('eclipse', 'eclipse'),
            ('studio', 'studio'),
            ('java', 'java'),
            ('smali', 'smali'),
            ('apk', 'apk'),
            ('jar', 'jar'),
            ('aar', 'aar'),
            ('so', 'so'),
            ('a', 'a')))


class ViewSourceIOSApiForm(AttackDetect, IOSChecks, APIChecks):
    pass


class ViewSourceIOSForm(AttackDetect, IOSChecks, WebChecks):
    pass


class ViewSourceAndroidApiForm(AttackDetect, AndroidChecks, APIChecks):
    pass


class ViewSourceAndroidForm(AttackDetect, AndroidChecks, WebChecks):
    pass
