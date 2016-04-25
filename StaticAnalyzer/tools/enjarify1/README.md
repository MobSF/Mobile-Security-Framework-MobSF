### Introduction

Enjarify is a tool for translating Dalvik bytecode to equivalent Java bytecode. This allows Java analysis tools to analyze Android applications.


### Usage and installation

Enjarify is a pure python 3 application, so you can just git clone and run it. To run it directly, assuming you are in the top directory of the repository, you can just do

    python3 -O -m enjarify.main yourapp.apk

For normal use, you'll probably want to use the wrapper scripts and set it up on your path.

#### Linux

For convenience, a wrapper shell script is provided, enjarify.sh. This will try to use Pypy if available, since it is faster than CPython. If you want to be able to call Enjarify from anywhere, you can create a symlink from somewhere on your PATH, such as ~/bin. To do this, assuming you are inside the top level of the repository,

    ln -s "$PWD/enjarify.sh" ~/bin/enjarify

#### Windows

A wrapper batch script, enjarify.bat, is provided. To be able to call it from anywhere, just add the root directory of the repository to your PATH. The batch script will always invoke python3 as interpreter. If you want to use pypy, just edit the script.

#### Usage

Assuming you set up the script on your path correctly, you can call it from anywhere by just typing enjarify, e.g.

    enjarify yourapp.apk

The most basic form of usage is to just specify an apk file or dex file as input. If you specify a multidex apk, Enjarify will automatically translate all of the dex files and output the results in a single combined jar. If you specify a dex file, only that dex file will be translated. E.g. assuming you manually extracted the dex files you could do

    enjarify classes2.dex

The default output file is [inputname]-enjarify.jar in the current directory. To specify the filename for the output explicitly, pass the -o or --output option.

    enjarify yourapp.apk -o yourapp.jar

By default, Enjarify will refuse to overwrite the output file if it already exists. To overwrite the output, pass the -f or --force option.


### Why not dex2jar?

Dex2jar is an older tool that also tries to translate Dalvik to Java bytecode. It works reasonable well most of the time, but a lot of obscure features or edge cases will cause it to fail or even silently produce incorrect results. By contrast, Enjarify is designed to work in as many cases as possible, even for code where Dex2jar would fail. Among other things, Enjarify correctly handles unicode class names, constants used as multiple types, implicit casts, exception handlers jumping into normal control flow, classes that reference too many constants, very long methods, exception handlers after a catchall handler, and static initial values of the wrong type.


### Limitations

Enjarify does not currently translate optional metadata such as sourcefile attributes, line numbers, and annotations.

Enjarify tries hard to successfully translate as many classes as possible, but there are some potential cases where it is simply not possible due to limitations in Android, Java, or both. Luckily, this only happens in contrived circumstances, so it shouldn't be a problem in practice.


### Performance tips

PyPy is much faster than CPython. To install PyPy, see http://pypy.org/. Make sure you get PyPy3 rather than regular PyPy. The Linux wrapper script will automatically use the command pypy3 if available. On Windows, you'll need to edit the wrapper script yourself.

By default, Enjarify runs optimizations on the bytecode which make it more readable for humans (copy propagation, unused value removal, etc.). If you don't need this, you can speed things up by disabling the optimizations with the --fast option. Note that in the very rare case where a class is too big to fit in a classfile without optimization, Enjarify will automatically retry it with all optimizations enabled, so this option does not affect the number of classes that are successfully translated.


### Disclaimer

This is not an official Google product (experimental or otherwise), it is just code that happens to be owned by Google.
