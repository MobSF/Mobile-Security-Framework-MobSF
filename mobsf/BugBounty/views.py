"""Session-authenticated, project-isolated UI and JSON API."""
import csv
from functools import wraps
from hashlib import sha256
from io import StringIO
import json
from uuid import uuid4

from django.conf import settings
from django.contrib.auth.decorators import login_required, permission_required
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from mobsf.BugBounty.forms import (
    CaptureForm, EvidenceForm, FindingForm, ImportForm, ProgramForm, ReviewForm,
)
from mobsf.BugBounty.models import Analysis, Finding, Program
from mobsf.BugBounty.proxy_import import burp_items
from mobsf.BugBounty.sanitization import sanitize
from mobsf.BugBounty.scope import classify
from mobsf.BugBounty.services import (
    add_evidence, add_finding, import_core, import_har, review_finding,
)


def owned(queryset, user, prefix=''):
    if user.is_superuser:
        return queryset
    return queryset.filter(**{prefix + 'owner': user})


def program_for(request, pk):
    return get_object_or_404(owned(Program.objects.all(), request.user), pk=pk)


def analysis_for(request, pk):
    return get_object_or_404(owned(
        Analysis.objects.select_related('program'), request.user, 'program__'),
        pk=pk)


def finding_for(request, pk):
    return get_object_or_404(owned(Finding.objects.select_related(
        'analysis__program'), request.user, 'analysis__program__'), pk=pk)


def bounded(view):
    @wraps(view)
    def wrapper(request, *args, **kwargs):
        try:
            size = int(request.META.get('CONTENT_LENGTH') or 0)
            if size > settings.BOUNTY_MAX_IMPORT_BYTES:
                return JsonResponse({'error': 'Request too large'}, status=413)
            return view(request, *args, **kwargs)
        except (ValueError, RecursionError) as exc:
            return JsonResponse({'error': str(exc)}, status=400)
    return wrapper


def payload(request):
    if request.content_type == 'application/json':
        if len(request.body) > settings.BOUNTY_MAX_IMPORT_BYTES:
            raise ValueError('Request too large')
        data = json.loads(request.body)
        if not isinstance(data, dict):
            raise ValueError('Expected a JSON object')
        if isinstance(data.get('rules'), dict):
            data['rules'] = json.dumps(data['rules'])
        return data
    return request.POST


def validated(form):
    if not form.is_valid():
        raise ValueError(form.errors.as_json())
    return form.cleaned_data


def endpoint_data(endpoint):
    program = endpoint.analysis.program
    refs = endpoint.analysis.findings.filter(
        kind='endpoint', fingerprint=sha256(
            ('endpoint\n' + endpoint.fingerprint).encode()).hexdigest())
    evidence_ids = list(refs.values_list('evidence__pk', flat=True).filter(
        evidence__expires_at__gt=timezone.now()))
    return {
        'endpoint_id': endpoint.fingerprint,
        'host': endpoint.host, 'path': endpoint.path,
        'url': endpoint.url, 'method': endpoint.method or None,
        'methods': endpoint.methods,
        'parameters': endpoint.parameters, 'sources': endpoint.sources,
        'scope_status': classify(endpoint.url, program),
        'confidence': endpoint.confidence, 'observed': endpoint.observed,
        'protocol': endpoint.protocol,
        'first_seen': endpoint.first_seen, 'last_seen': endpoint.last_seen,
        'evidence_refs': evidence_ids,
    }


@login_required
@require_http_methods(['GET', 'POST'])
@bounded
def programs(request):
    if request.method == 'POST':
        form = ProgramForm(payload(request))
        validated(form)
        program = form.save(commit=False)
        program.owner = request.user
        program.save()
        if request.path.startswith('/bounty/api/'):
            return JsonResponse({'id': program.pk}, status=201)
        return redirect('bounty_program', pk=program.pk)
    queryset = owned(Program.objects.all(), request.user).order_by('-pk')
    query = request.GET.get('q', '')[:160]
    queryset = queryset.filter(name__icontains=query)
    page = Paginator(queryset, 25).get_page(request.GET.get('page'))
    if request.path.startswith('/bounty/api/'):
        return JsonResponse({'programs': list(page.object_list.values(
            'id', 'name', 'approved')), 'pages': page.paginator.num_pages})
    return render(request, 'bounty/programs.html', {
        'title': 'Bug Bounty Workspace', 'version': settings.MOBSF_VER,
        'page': page, 'query': query,
        'form': ProgramForm(initial={'rules': json.dumps({
            'allowed_domains': ['api.example.test'],
            'allowed_subdomains': [], 'excluded_domains': [],
            'excluded_paths': ['/admin']}, indent=2)}),
    })


@login_required
@require_http_methods(['GET', 'POST'])
@bounded
def program_detail(request, pk):
    program = program_for(request, pk)
    if request.method == 'POST':
        form = ProgramForm(payload(request), instance=program)
        validated(form)
        form.save()
        if request.path.startswith('/bounty/api/'):
            return JsonResponse({'id': program.pk})
        return redirect('bounty_program', pk=pk)
    if request.path.startswith('/bounty/api/'):
        return JsonResponse({'id': program.pk, 'name': program.name,
                             'rules': program.rules,
                             'approved': program.approved,
                             'authorization_source': program.authorization_source,
                             'authorized_at': program.authorized_at})
    return render(request, 'bounty/program.html', {
        'title': program.name, 'version': settings.MOBSF_VER,
        'program': program, 'analyses': program.analyses.order_by('-pk'),
        'import_form': ImportForm(),
        'form': ProgramForm(instance=program, initial={
            'rules': json.dumps(program.rules, indent=2)}),
    })


@login_required
@permission_required('StaticAnalyzer.can_scan', raise_exception=True)
@require_http_methods(['POST'])
@bounded
def core_import(request, pk):
    program = program_for(request, pk)
    data = validated(ImportForm(payload(request)))
    analysis = import_core(program, data['checksum'])
    if request.path.startswith('/bounty/api/'):
        return JsonResponse({'analysis_id': analysis.pk})
    return redirect('bounty_analysis', pk=analysis.pk)


@login_required
@require_http_methods(['GET'])
def analysis_detail(request, pk):
    analysis = analysis_for(request, pk)
    query = request.GET.get('q', '')[:160]
    endpoints = analysis.endpoints.filter(
        Q(host__icontains=query) | Q(path__icontains=query)).order_by('pk')
    scope_filter = request.GET.get('scope', '')
    # Classification is evaluated against current rules, never stale imported rules.
    if scope_filter in ('IN_SCOPE', 'OUT_OF_SCOPE', 'UNKNOWN'):
        ids = [ep.pk for ep in endpoints if classify(
            ep.url, analysis.program) == scope_filter]
        endpoints = endpoints.filter(pk__in=ids)
    page = Paginator(endpoints, 50).get_page(request.GET.get('page'))
    records = [endpoint_data(endpoint) for endpoint in page]
    findings = analysis.findings.order_by('pk')
    state = request.GET.get('status', '')
    if state in dict(Finding.STATES):
        findings = findings.filter(status=state)
    finding_page = Paginator(findings, 25).get_page(request.GET.get('findings_page'))
    if request.path.startswith('/bounty/api/'):
        return JsonResponse({'analysis_id': analysis.pk, 'endpoints': records,
                             'pages': page.paginator.num_pages,
                             'findings': list(finding_page.object_list.values(
                                 'id', 'title', 'kind', 'severity',
                                 'confidence', 'status'))})
    return render(request, 'bounty/analysis.html', {
        'title': 'API Inventory', 'version': settings.MOBSF_VER,
        'analysis': analysis, 'records': records, 'page': page,
        'findings_page': finding_page, 'query': query,
        'finding_form': FindingForm(),
    })


@login_required
@require_http_methods(['POST'])
@bounded
def har_import(request, pk):
    analysis = analysis_for(request, pk)
    source = 'HAR'
    if request.content_type == 'application/json':
        data = payload(request)
    else:
        upload = request.FILES.get('har')
        if not upload or upload.size > settings.BOUNTY_MAX_IMPORT_BYTES:
            return JsonResponse(
                {'error': 'Capture required, maximum 2 MiB'}, status=400,
            )
        form = CaptureForm({'format': request.POST.get('format', 'har')})
        kind = validated(form)['format']
        raw = upload.read()
        if kind == 'burp':
            data = burp_items(raw)
            source = 'Burp Suite Professional XML'
        else:
            data = json.loads(raw)
            source = 'Caido HAR' if kind == 'caido' else 'HAR'
    count = import_har(analysis, data, source)
    if request.path.startswith('/bounty/api/'):
        return JsonResponse({'imported': count})
    return redirect('bounty_analysis', pk=pk)


@login_required
@require_http_methods(['POST'])
@bounded
def finding_create(request, pk):
    analysis = analysis_for(request, pk)
    data = validated(FindingForm(payload(request)))
    finding = add_finding(analysis, 'manual', str(uuid4()), **data)
    if request.path.startswith('/bounty/api/'):
        return JsonResponse({'finding_id': finding.pk}, status=201)
    return redirect('bounty_finding', pk=finding.pk)


@login_required
@require_http_methods(['GET', 'POST'])
@bounded
def finding_detail(request, pk):
    finding = finding_for(request, pk)
    if request.method == 'POST':
        data = validated(ReviewForm(payload(request)))
        finding = review_finding(finding, request.user, **data)
        if request.path.startswith('/bounty/api/'):
            return JsonResponse({'id': finding.pk, 'status': finding.status})
        return redirect('bounty_finding', pk=pk)
    evidence = finding.evidence.filter(expires_at__gt=timezone.now())
    events = finding.events.order_by('created_at')
    if request.path.startswith('/bounty/api/'):
        return JsonResponse({
            'id': finding.pk, 'title': finding.title, 'status': finding.status,
            'severity': finding.severity, 'confidence': finding.confidence,
            'rationale': finding.rationale,
            'evidence': list(evidence.values()),
            'events': list(events.values('actor_id', 'previous_status',
                                         'status', 'note', 'created_at')),
        })
    return render(request, 'bounty/finding.html', {
        'title': finding.title, 'version': settings.MOBSF_VER,
        'finding': finding, 'evidence': evidence, 'events': events,
        'form': ReviewForm(initial={
            'status': finding.status, 'severity': finding.severity,
            'note': finding.review_note}),
        'evidence_form': EvidenceForm(),
    })


@login_required
@require_http_methods(['POST'])
@bounded
def evidence_create(request, pk):
    finding = finding_for(request, pk)
    data = validated(EvidenceForm(payload(request)))
    evidence = add_evidence(finding, **data)
    if request.path.startswith('/bounty/api/'):
        return JsonResponse({'evidence_id': evidence.pk}, status=201)
    return redirect('bounty_finding', pk=pk)


def csv_safe(value):
    text = str(value)
    if text.lstrip().startswith(('=', '+', '-', '@')):
        return "'" + text
    return text


@login_required
@require_http_methods(['GET'])
def inventory_export(request, pk, fmt):
    analysis = analysis_for(request, pk)
    records = [endpoint_data(ep) for ep in analysis.endpoints.order_by('pk')]
    if fmt == 'json':
        response = JsonResponse({'endpoints': records})
    elif fmt == 'csv':
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['endpoint_id', 'host', 'path', 'method', 'parameters',
                         'scope_status', 'observed', 'confidence', 'sources'])
        for record in records:
            writer.writerow([csv_safe(record[key]) for key in (
                'endpoint_id', 'host', 'path', 'method', 'parameters',
                'scope_status', 'observed', 'confidence', 'sources')])
        response = HttpResponse(output.getvalue(), content_type='text/csv')
    else:
        return JsonResponse({'error': 'Unsupported export'}, status=400)
    response['Content-Disposition'] = 'attachment; filename="inventory.' + fmt + '"'
    return response


@login_required
@require_http_methods(['GET'])
def compare_versions(request, pk, other):
    first, second = analysis_for(request, pk), analysis_for(request, other)
    if (first.program_id != second.program_id or not first.package
            or first.package != second.package):
        return JsonResponse({'error': 'Select versions of the same application'},
                            status=400)
    a = set(first.findings.values_list('fingerprint', flat=True))
    b = set(second.findings.values_list('fingerprint', flat=True))
    return JsonResponse({'added': sorted(b - a), 'removed': sorted(a - b),
                         'unchanged': sorted(a & b)})


@login_required
@require_http_methods(['GET'])
def finding_report(request, pk, fmt):
    finding = finding_for(request, pk)
    content = sanitize({
        'title': finding.title, 'asset': finding.analysis.package,
        'status': finding.status, 'severity': finding.severity,
        'confidence': finding.confidence, 'description': finding.rationale,
        'review_note': finding.review_note,
        'evidence': list(finding.evidence.filter(
            expires_at__gt=timezone.now()).values('kind', 'source', 'content')),
    })
    if fmt == 'json':
        return JsonResponse(content)
    if fmt == 'md':
        text = '# ' + content['title'] + '\n\n' + '\n\n'.join(
            key + ': ' + str(value) for key, value in content.items())
        response = HttpResponse(text, content_type='text/markdown')
        response['Content-Disposition'] = 'attachment; filename="finding.md"'
        return response
    return JsonResponse({'error': 'Unsupported report format'}, status=400)
