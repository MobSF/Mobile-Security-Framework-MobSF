<img src="https://raw.githubusercontent.com/skylot/jadx/master/jadx-gui/src/main/resources/logos/jadx-logo.png" width="64" align="left" />

## JADX

[![Build status](https://github.com/skylot/jadx/workflows/Build/badge.svg)](https://github.com/skylot/jadx/actions?query=workflow%3ABuild)
[![Alerts from lgtm.com](https://img.shields.io/lgtm/alerts/g/skylot/jadx.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/skylot/jadx/alerts/)
[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.skylot/jadx-core)](https://search.maven.org/search?q=g:io.github.skylot%20AND%20jadx)
[![License](http://img.shields.io/:license-apache-blue.svg)](http://www.apache.org/licenses/LICENSE-2.0.html)

**jadx** - Dex to Java decompiler

Command line and GUI tools for producing Java source code from Android Dex and Apk files

:exclamation::exclamation::exclamation: Please note that in most cases **jadx** can't decompile all 100% of the code, so errors will occur. Check [Troubleshooting guide](https://github.com/skylot/jadx/wiki/Troubleshooting-Q&A#decompilation-issues) for workarounds

**Main features:**
- decompile Dalvik bytecode to java classes from APK, dex, aar, aab and zip files
- decode `AndroidManifest.xml` and other resources from `resources.arsc`
- deobfuscator included

**jadx-gui features:**
- view decompiled code with highlighted syntax
- jump to declaration
- find usage
- full text search
- smali debugger, check [wiki page](https://github.com/skylot/jadx/wiki/Smali-debugger) for setup and usage

Jadx-gui key bindings can be found [here](https://github.com/skylot/jadx/wiki/JADX-GUI-Key-bindings)

See these features in action here: [jadx-gui features overview](https://github.com/skylot/jadx/wiki/jadx-gui-features-overview)

<img src="https://user-images.githubusercontent.com/118523/142730720-839f017e-38db-423e-b53f-39f5f0a0316f.png" width="700"/>

### Download
- release from [github: ![Latest release](https://img.shields.io/github/release/skylot/jadx.svg)](https://github.com/skylot/jadx/releases/latest)
- latest [unstable build](https://nightly.link/skylot/jadx/workflows/build/master)

After download unpack zip file go to `bin` directory and run:
- `jadx` - command line version
- `jadx-gui` - UI version

On Windows run `.bat` files with double-click\
**Note:** ensure you have installed Java 11 or later 64-bit version.
For Windows, you can download it from [oracle.com](https://www.oracle.com/java/technologies/downloads/#jdk17-windows) (select x64 Installer).

### Install
1. Arch linux
    ```bash
        sudo pacman -S jadx
    ```
2. macOS
    ```bash
        brew install jadx
    ```

### Use jadx as a library
You can use jadx in your java projects, check details on [wiki page](https://github.com/skylot/jadx/wiki/Use-jadx-as-a-library)

### Build from source
JDK 8 or higher must be installed:
```
git clone https://github.com/skylot/jadx.git
cd jadx
./gradlew dist
```

(on Windows, use `gradlew.bat` instead of `./gradlew`)

Scripts for run jadx will be placed in `build/jadx/bin`
and also packed to `build/jadx-<version>.zip`

### Usage
```
jadx[-gui] [options] <input files> (.apk, .dex, .jar, .class, .smali, .zip, .aar, .arsc, .aab)
options:
  -d, --output-dir                    - output directory
  -ds, --output-dir-src               - output directory for sources
  -dr, --output-dir-res               - output directory for resources
  -r, --no-res                        - do not decode resources
  -s, --no-src                        - do not decompile source code
  --single-class                      - decompile a single class, full name, raw or alias
  --single-class-output               - file or dir for write if decompile a single class
  --output-format                     - can be 'java' or 'json', default: java
  -e, --export-gradle                 - save as android gradle project
  -j, --threads-count                 - processing threads count, default: 4
  -m, --decompilation-mode            - code output mode:
                                         'auto' - trying best options (default)
                                         'restructure' - restore code structure (normal java code)
                                         'simple' - simplified instructions (linear, with goto's)
                                         'fallback' - raw instructions without modifications
  --show-bad-code                     - show inconsistent code (incorrectly decompiled)
  --no-imports                        - disable use of imports, always write entire package name
  --no-debug-info                     - disable debug info
  --add-debug-lines                   - add comments with debug line numbers if available
  --no-inline-anonymous               - disable anonymous classes inline
  --no-inline-methods                 - disable methods inline
  --no-replace-consts                 - don't replace constant value with matching constant field
  --escape-unicode                    - escape non latin characters in strings (with \u)
  --respect-bytecode-access-modifiers - don't change original access modifiers
  --deobf                             - activate deobfuscation
  --deobf-min                         - min length of name, renamed if shorter, default: 3
  --deobf-max                         - max length of name, renamed if longer, default: 64
  --deobf-cfg-file                    - deobfuscation map file, default: same dir and name as input file with '.jobf' extension
  --deobf-cfg-file-mode               - set mode for handle deobfuscation map file:
                                         'read' - read if found, don't save (default)
                                         'read-or-save' - read if found, save otherwise (don't overwrite)
                                         'overwrite' - don't read, always save
                                         'ignore' - don't read and don't save
  --deobf-rewrite-cfg                 - set '--deobf-cfg-file-mode' to 'overwrite' (deprecated)
  --deobf-use-sourcename              - use source file name as class name alias
  --deobf-parse-kotlin-metadata       - parse kotlin metadata to class and package names
  --use-kotlin-methods-for-var-names  - use kotlin intrinsic methods to rename variables, values: disable, apply, apply-and-hide, default: apply
  --rename-flags                      - fix options (comma-separated list of):
                                         'case' - fix case sensitivity issues (according to --fs-case-sensitive option),
                                         'valid' - rename java identifiers to make them valid,
                                         'printable' - remove non-printable chars from identifiers,
                                        or single 'none' - to disable all renames
                                        or single 'all' - to enable all (default)
  --fs-case-sensitive                 - treat filesystem as case sensitive, false by default
  --cfg                               - save methods control flow graph to dot file
  --raw-cfg                           - save methods control flow graph (use raw instructions)
  -f, --fallback                      - set '--decompilation-mode' to 'fallback' (deprecated)
  --use-dx                            - use dx/d8 to convert java bytecode
  --comments-level                    - set code comments level, values: error, warn, info, debug, user-only, none, default: info
  --log-level                         - set log level, values: quiet, progress, error, warn, info, debug, default: progress
  -v, --verbose                       - verbose output (set --log-level to DEBUG)
  -q, --quiet                         - turn off output (set --log-level to QUIET)
  --version                           - print jadx version
  -h, --help                          - print this help

Plugin options (-P<name>=<value>):
  1) dex-input (Load .dex and .apk files)
    -Pdex-input.verify-checksum       - Verify dex file checksum before load, values: [yes, no], default: yes
  2) java-convert (Convert .jar and .class files to dex)
    -Pjava-convert.mode               - Convert mode, values: [dx, d8, both], default: both
    -Pjava-convert.d8-desugar         - Use desugar in d8, values: [yes, no], default: no

Examples:
  jadx -d out classes.dex
  jadx --rename-flags "none" classes.dex
  jadx --rename-flags "valid, printable" classes.dex
  jadx --log-level ERROR app.apk
  jadx -Pdex-input.verify-checksum=no app.apk
```
These options also worked on jadx-gui running from command line and override options from preferences dialog

### Troubleshooting
Please check wiki page [Troubleshooting Q&A](https://github.com/skylot/jadx/wiki/Troubleshooting-Q&A)

### Contributing
To support this project you can:
  - Post thoughts about new features/optimizations that important to you
  - Submit decompilation issues, please read before proceed: [Open issue](CONTRIBUTING.md#Open-Issue)
  - Open pull request, please follow these rules: [Pull Request Process](CONTRIBUTING.md#Pull-Request-Process)

---------------------------------------
*Licensed under the Apache 2.0 License*
