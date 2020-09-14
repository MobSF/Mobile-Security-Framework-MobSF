import platform

from pkg_resources import (
    DistributionNotFound,
    VersionConflict,
    require,
)

from pathlib import Path

plat = platform.system() != 'Windows'
red = '\033[91m' if plat else ''
end = '\033[0m' if plat else ''
bold = '\033[1m' if plat else ''
req = Path(__file__).resolve().parents[1] / 'requirements.txt'
dependencies = req.read_text().splitlines()

try:
    require(dependencies)
except VersionConflict:
    pass
except DistributionNotFound as exp:
    print(f'{red}{bold}[ERROR] Installation Failed!{end}{red}\n'
          f'Please ensure that all the requirements '
          f'mentioned in documentation are installed '
          f'before you run setup script.\nScroll up to see any '
          f'installtion errors.\n\n{exp}{end}')
    exit(1)
