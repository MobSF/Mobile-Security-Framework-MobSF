"""Bounded, validated inputs for the passive workspace."""
import json

import yaml

from django import forms

from mobsf.BugBounty.models import Finding, Program
from mobsf.BugBounty.sanitization import redact_text
from mobsf.BugBounty.scope import validate_rules
from mobsf.MobSF.security import is_path_traversal


class ProgramForm(forms.ModelForm):
    rules = forms.CharField(widget=forms.Textarea, max_length=65536)
    authorized_at = forms.DateTimeField(required=False)

    class Meta:
        """Editable program fields; ownership is assigned by the server."""

        model = Program
        fields = ['name', 'rules', 'authorization_source',
                  'authorized_at', 'approved']

    def clean_rules(self):
        value = self.cleaned_data['rules']
        try:
            try:
                data = json.loads(value)
            except json.JSONDecodeError:
                if any(isinstance(token, (yaml.tokens.AliasToken,
                                          yaml.tokens.AnchorToken))
                       for token in yaml.scan(value)):
                    raise ValueError('YAML aliases are not permitted')
                data = yaml.safe_load(value)
            return validate_rules(data)
        except (ValueError, yaml.YAMLError, RecursionError) as exc:
            raise forms.ValidationError(str(exc)) from exc

    def clean(self):
        data = super().clean()
        if data.get('approved') and not (data.get('authorization_source')
                                         and data.get('authorized_at')):
            raise forms.ValidationError(
                'Approval requires authorization source and date')
        for key in ('name', 'authorization_source'):
            if key in data:
                data[key] = redact_text(data[key])
        return data


class ImportForm(forms.Form):
    checksum = forms.RegexField(regex=r'\A[0-9a-f]{32}\Z', max_length=32)


class ReviewForm(forms.Form):
    status = forms.ChoiceField(choices=Finding.STATES)
    severity = forms.ChoiceField(choices=Finding.SEVERITIES)
    note = forms.CharField(widget=forms.Textarea, max_length=10000)


class EvidenceForm(forms.Form):
    kind = forms.ChoiceField(choices=[(v, v) for v in (
        'source', 'http', 'frida', 'log', 'manual')])
    source = forms.CharField(max_length=500)
    content = forms.CharField(widget=forms.Textarea, max_length=65536)

    def clean_source(self):
        source = self.cleaned_data['source']
        if is_path_traversal(source) or any(ord(c) < 32 for c in source):
            raise forms.ValidationError('Invalid evidence source reference')
        return source


class FindingForm(forms.Form):
    title = forms.CharField(max_length=300)
    rationale = forms.CharField(widget=forms.Textarea, max_length=10000)
    severity = forms.ChoiceField(choices=Finding.SEVERITIES)
