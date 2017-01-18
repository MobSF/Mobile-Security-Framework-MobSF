from androguard.core import *
from androguard.core.androgen import *
from androguard.core.bytecode import *
from androguard.core.bytecodes.dvm import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *
from androguard.core.analysis.ganalysis import *
from androguard.decompiler.decompiler import *

from cPickle import dumps, loads
from androguard.core import androconf

def save_session(l, filename):
  """
      save your session !

      :param l: a list of objects
      :type: a list of object
      :param filename: output filename to save the session
      :type filename: string

      :Example:
          save_session([a, vm, vmx], "msession.json")
  """
  with open(filename, "w") as fd:
     fd.write(dumps(l, -1))

def load_session(filename):
  """
      load your session !

      :param filename: the filename where the session has been saved
      :type filename: string

      :rtype: the elements of your session :)

      :Example:
          a, vm, vmx = load_session("mysession.json")
  """
  return loads(read(filename, binary=False))

def AnalyzeAPK(filename, raw=False, decompiler="dad"):
    """
        Analyze an android application and setup all stuff for a more quickly analysis !

        :param filename: the filename of the android application or a buffer which represents the application
        :type filename: string
        :param raw: True is you would like to use a buffer (optional)
        :type raw: boolean
        :param decompiler: ded, dex2jad, dad (optional)
        :type decompiler: string

        :rtype: return the :class:`APK`, :class:`DalvikVMFormat`, and :class:`VMAnalysis` objects
    """
    androconf.debug("APK ...")
    a = APK(filename, raw)
    d, dx = AnalyzeDex(a.get_dex(), raw=True, decompiler=decompiler)
    return a, d, dx

def AnalyzeDex(filename, raw=False, decompiler="dad"):
    """
        Analyze an android dex file and setup all stuff for a more quickly analysis !

        :param filename: the filename of the android dex file or a buffer which represents the dex file
        :type filename: string
        :param raw: True is you would like to use a buffer (optional)
        :type raw: boolean

        :rtype: return the :class:`DalvikVMFormat`, and :class:`VMAnalysis` objects
    """
    androconf.debug("DalvikVMFormat ...")

    d = None
    if raw == False:
        d = DalvikVMFormat(read(filename))
    else:
        d = DalvikVMFormat(filename)

    androconf.debug("Export VM to python namespace")
    d.create_python_export()

    androconf.debug("VMAnalysis ...")
    dx = uVMAnalysis(d)

    androconf.debug("GVMAnalysis ...")
    gx = GVMAnalysis(dx, None)

    d.set_vmanalysis(dx)
    d.set_gvmanalysis(gx)

    RunDecompiler(d, dx, decompiler)

    androconf.debug("XREF ...")
    d.create_xref()
    androconf.debug("DREF ...")
    d.create_dref()

    return d, dx


def AnalyzeODex(filename, raw=False, decompiler="dad"):
    """
        Analyze an android odex file and setup all stuff for a more quickly analysis !

        :param filename: the filename of the android dex file or a buffer which represents the dex file
        :type filename: string
        :param raw: True is you would like to use a buffer (optional)
        :type raw: boolean

        :rtype: return the :class:`DalvikOdexVMFormat`, and :class:`VMAnalysis` objects
    """
    androconf.debug("DalvikOdexVMFormat ...")
    d = None
    if raw == False:
        d = DalvikOdexVMFormat(read(filename))
    else:
        d = DalvikOdexVMFormat(filename)

    androconf.debug("Export VM to python namespace")
    d.create_python_export()

    androconf.debug("VMAnalysis ...")
    dx = uVMAnalysis(d)

    androconf.debug("GVMAnalysis ...")
    gx = GVMAnalysis(dx, None)

    d.set_vmanalysis(dx)
    d.set_gvmanalysis(gx)

    RunDecompiler(d, dx, decompiler)

    androconf.debug("XREF ...")
    d.create_xref()
    androconf.debug("DREF ...")
    d.create_dref()

    return d, dx


def RunDecompiler(d, dx, decompiler):
    """
        Run the decompiler on a specific analysis

        :param d: the DalvikVMFormat object
        :type d: :class:`DalvikVMFormat` object
        :param dx: the analysis of the format
        :type dx: :class:`VMAnalysis` object
        :param decompiler: the type of decompiler to use ("dad", "dex2jad", "ded")
        :type decompiler: string
    """
    if decompiler != None:
      androconf.debug("Decompiler ...")
      decompiler = decompiler.lower()
      if decompiler == "dex2jad":
        d.set_decompiler(DecompilerDex2Jad(d,
                                           androconf.CONF["PATH_DEX2JAR"],
                                           androconf.CONF["BIN_DEX2JAR"],
                                           androconf.CONF["PATH_JAD"],
                                           androconf.CONF["BIN_JAD"],
                                           androconf.CONF["TMP_DIRECTORY"]))
      elif decompiler == "dex2fernflower":
        d.set_decompiler(DecompilerDex2Fernflower(d,
                                                  androconf.CONF["PATH_DEX2JAR"],
                                                  androconf.CONF["BIN_DEX2JAR"],
                                                  androconf.CONF["PATH_FERNFLOWER"],
                                                  androconf.CONF["BIN_FERNFLOWER"],
                                                  androconf.CONF["OPTIONS_FERNFLOWER"],
                                                  androconf.CONF["TMP_DIRECTORY"]))
      elif decompiler == "ded":
        d.set_decompiler(DecompilerDed(d,
                                       androconf.CONF["PATH_DED"],
                                       androconf.CONF["BIN_DED"],
                                       androconf.CONF["TMP_DIRECTORY"]))
      else:
        d.set_decompiler(DecompilerDAD(d, dx))


def AnalyzeElf(filename, raw=False):
    # avoid to install smiasm for everybody
    from androguard.core.binaries.elf import ELF

    e = None
    if raw == False:
        e = ELF(read(filename))
    else:
        e = ELF(filename)

    ExportElfToPython(e)

    return e


def ExportElfToPython(e):
    for function in e.get_functions():
        name = "FUNCTION_" + function.name
        setattr(e, name, function)
