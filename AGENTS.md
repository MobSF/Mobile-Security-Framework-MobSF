# MobSF Agent Guidelines

MobSF is a security analysis platform. Every code path processes attacker-supplied
input (APKs, ZIPs, IPAs, manifests) from authenticated but potentially malicious
users. Security must be the default, not an afterthought.

---

## Code Quality — Mandatory Before Every Commit

Run lint and fix all errors before finishing any task:

```bash
tox -e lint
```

Never leave a task with a non-zero exit code from this command.

---

## Security Architecture

Centralized security helpers live in **`mobsf/MobSF/security.py`**. When adding new
security checks, prefer adding them there. Some legacy validators still live in
`mobsf/MobSF/utils.py`; use existing helpers where they are already established.

### Available Security Functions

Import only the helpers needed for the change:

```python
from mobsf.MobSF.security import (
    # Path safety
    is_path_traversal,   # Check raw string for .. sequences, absolute paths, URL encoding tricks
    is_safe_path,        # Containment check after path construction via realpath()

    # Input validation
    is_attack_pattern,   # Detect shell injection: ;, $(), ||, &&
    cmd_injection_check, # Detect OS command injection characters
    is_pipe_or_link,     # Detect symlinks and named FIFOs before reading files

    # Output sanitization
    sanitize_filename,   # Safe filename for Content-Disposition headers
    sanitize_for_logging,# Strip newlines and control chars before logging user input
    sanitize_redirect,   # Allow only relative paths in redirects
    sanitize_svg,        # Strip XSS vectors from SVG content (bleach-based)
    clean_filename,      # Windows-safe filename (unicode normalization)

    # Network / SSRF
    valid_host,          # DNS-resolves host; rejects private/loopback/multicast IPs
)
```

---

## Past Vulnerabilities and Insecure Patterns

Read `.github/SECURITY.md` to understand the full history of security issues in this
codebase. Use it as a guide for what classes of bugs to watch for and what patterns
have been exploited before. When in doubt about whether a pattern is safe, check
whether a similar pattern has appeared in the advisory history.

---

## Incomplete Fix Anti-Pattern

The most common source of security regressions in this codebase is applying a fix to
one code path but not its siblings. Before closing any security fix:

1. Search for all functions or patterns that perform the same operation (e.g., every
   place that resolves an icon path, every place that extracts an archive entry).
2. Verify the fix is applied consistently across **all** of them.
3. Check both the APK binary flow and the source-ZIP flow — they are separate code paths
   with separate callsites and have diverged in the past.

---

## Input Trust Model

- `request.GET` / `request.POST`: untrusted. Validate with forms or explicit checks;
  escape on output.
- File uploads: untrusted. Validate magic bytes, size limits, and extension allowlists.
- Archive entries (`zip`, `tar`, `ar`): untrusted. Check each entry before extraction.
- `AndroidManifest.xml` values: untrusted. Treat as attacker-controlled before using
  them in filesystem operations or rendering them.
- `Info.plist` values: untrusted. Apply the same treatment as manifest values.
- `md5` / `hash` URL parameters: semi-trusted only after validation. Always validate
  with `is_md5()` before using them in paths.
- Device identifiers: untrusted. Use command-injection checks plus format validation.

---

## Django-Specific Security Features

### Form Validation — The Primary Input Sanitization Layer

Prefer Django forms for new request validation. If a view does not use a form, validate
every `request.GET[...]` or `request.POST[...]` value explicitly before using it.

The project uses a mixin composition pattern. Combine the appropriate mixins rather than
writing ad-hoc validation in view code:

```python
# StaticAnalyzer/forms.py — mixins to compose from
AttackDetect   # is_path_traversal + extension allowlist on a 'file' param
APIChecks      # MD5 format check on a 'hash' param (API mode)
WebChecks      # MD5 format check on an 'md5' param (HTML mode)
AndroidChecks  # ChoiceField allowlist for Android scan type
IOSChecks      # ChoiceField allowlist for iOS scan type
```

Custom field validators belong in a `clean_<field>()` method that raises
`forms.ValidationError` on rejection — never return a partial result and check it in
the view. `FormUtil.errors_message(form)` produces the standard error envelope to return
to the caller when `form.is_valid()` is False.

**Use `ChoiceField` for any parameter with a finite set of valid values.** This
eliminates an entire class of injection risk at the form layer with no extra code.
Never use `CharField` and then manually compare the value against an allowlist in the
view — let the form do it.

### View Decorators — Apply All Three

Views that handle sensitive operations should use the applicable Django decorators for
authentication, authorization, and method restriction:

```python
@login_required
@permission_required(Permissions.SCAN)   # or DELETE, SUPPRESS, etc.
@require_http_methods(['POST'])           # or ['GET'] — never omit this
def my_view(request, api=False):
    ...
```

- `@login_required` blocks unauthenticated access.
- `@permission_required` enforces role-based access beyond authentication.
- `@require_http_methods` rejects wrong HTTP verbs before any logic runs,
  preventing CSRF-via-GET and other method-confusion issues.

### Template Auto-Escaping

Django's template engine escapes variables by default. Do **not** use `{% autoescape off %}`
or the `|safe` filter on any value derived from scan data, manifests, or user input.
When rendering user-controlled strings outside of templates (e.g., in a JSON response
built by hand), use `django.utils.html.escape()` explicitly.

### ORM — No Raw SQL

Use the Django ORM for all database access. Never use `.raw()` or string-formatted SQL.
When a queryset filter value comes from user input, pass it as a keyword argument
(the ORM parameterizes it automatically):

```python
# Correct
RecentScansDB.objects.filter(MD5=checksum)

# Wrong
RecentScansDB.objects.raw(f'SELECT * FROM ... WHERE MD5 = "{checksum}"')
```

### CSRF

Django's `CsrfViewMiddleware` is enabled globally. Do not use `@csrf_exempt` on any
view that modifies state. API endpoints that accept an `X-Csrftoken` header or use
token-based auth are the only legitimate exception, and that pattern is already
established in the existing API views.

---

## Archive Extraction Safety

### TAR

Never use a hand-rolled name-only check with `os.path.abspath`. The symlink +
nested-entry combination bypasses it: a symlink member named `escape` passes the
name check, gets extracted to disk, and then a file member named `escape/pwned.txt`
is written through the symlink to an arbitrary location.

`os.path.abspath` normalises `..` but does **not** resolve symlinks.
`os.path.realpath` resolves both — but even `realpath`-based checks that run before
extraction have a TOCTOU window.

Use Python 3.12's built-in filter instead (MobSF requires `python = "^3.12"`):

```python
# Correct — per-member, type-aware, symlink-aware
tar.extractall(dest, members=safe_members_generator, filter='data')

# Wrong — abspath-based name check; blind to symlinks
for member in tar.getmembers():
    if not os.path.abspath(join(dest, member.name)).startswith(dest):
        raise ...
tar.extractall(dest, members=...)
```

`filter='data'` rejects: symlinks outside destination, hardlinks outside destination,
absolute paths, path traversal, and device files — per member, before extraction.

For code that must support Python < 3.12, fall back to: skip all symlink and hardlink
members (`member.issym()` / `member.islnk()`), then use `realpath` for the boundary
check, and validate-then-extract per member rather than batch-validate-then-extractall.

### ZIP

Python's `zipfile` module does not create real filesystem symlinks from Unix symlink
entries — it writes the link target as plain file bytes. The TAR symlink attack does
not apply to ZIP extraction. Use `is_path_traversal` + `is_safe_path` for member name
validation and validate per-member before calling `zip_ref.extract(member, dest)`.

---

## Import Conventions

When adding new imports, maintain alphabetical order within each import group to satisfy
`flake8-import-order`. Group order: stdlib → third-party → Django → local MobSF.

---

## Checklist for Any Change That Touches File I/O or User Input

- [ ] Raw input validated with `is_path_traversal` before path construction
- [ ] Constructed filesystem paths verified with `is_safe_path` when a safe root exists
- [ ] Symlinks and FIFOs rejected with `is_pipe_or_link` before file reads
- [ ] Shell arguments passed as a list, not a formatted string
- [ ] User-controlled strings escaped with `django.utils.html.escape` before rendering
- [ ] SVG content piped through `sanitize_svg`
- [ ] Outbound URLs checked with `valid_host`
- [ ] Redirects wrapped in `sanitize_redirect`
- [ ] Log statements use `sanitize_for_logging` on any user-derived value
- [ ] TAR extraction uses `filter='data'` — not a hand-rolled `abspath` check
- [ ] ZIP extraction validates each member path with `realpath` before `extract()`
- [ ] Every security guard has `continue` / `return` / `raise` — logging alone is not a guard
- [ ] Fix applied symmetrically to all equivalent code paths
- [ ] `tox -e lint` passes with exit code 0
