"""Bundle tracked application source for the dependency-free Windows launcher."""

import hashlib
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIRECTORIES = ('mobsf/', 'scripts/', 'docker/', 'docs/', 'LICENSES/')
FILES = {
    'Dockerfile',
    '.dockerignore',
    'pyproject.toml',
    'poetry.lock',
    'manage.py',
    'README.md',
    'LICENSE',
}


def main():
    """Package source only; reject ignored data, symlinks and private artifacts."""
    records = subprocess.check_output(
        ['git', '-C', str(ROOT), 'ls-files', '--stage', '-z'],
    ).decode().split('\0')
    modes = {}
    for record in filter(None, records):
        metadata, name = record.split('\t', 1)
        mode, _, stage = metadata.split()
        if stage != '0':
            raise RuntimeError('Resolve Git conflicts before packaging')
        modes[name] = mode
    selected = sorted(
        name
        for name in modes
        if (name in FILES or name.startswith(DIRECTORIES))
        and name != 'mobsf/StaticAnalyzer/test_files'
        and not name.endswith(('.map', '.exe'))
    )
    if 'docker/desktop-compose.yml' not in selected:
        raise RuntimeError('Stage the desktop source files before packaging')
    destination = ROOT / 'desktop/resources/source.zip'
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        destination,
        'w',
        zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for name in selected:
            file = ROOT / name
            if file.is_symlink() or not file.is_file():
                raise RuntimeError(f'Invalid packaged source file: {name}')
            if name.startswith('mobsf/StaticAnalyzer/test_files/'):
                continue
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            if modes[name] not in ('100644', '100755'):
                raise RuntimeError(f'Invalid Git source mode: {name}')
            info.external_attr = int(modes[name], 8) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, file.read_bytes())
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    print(f'Bundled {len(selected)} source files; SHA256 {digest}')


if __name__ == '__main__':
    main()
