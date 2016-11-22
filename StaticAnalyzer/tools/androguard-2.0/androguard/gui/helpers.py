class Signature(object):

    def __init__(self, cls, method=None, descriptor=None):
        self.cls = cls
        self.class_components = self.cls.name.strip('L').strip(';').split('/')
        self.class_path = self.class_components[:-1]
        self.class_name = self.class_components[-1]
        self.full_class_name = self.cls.name
        self.method = method
        self.descriptor = descriptor

def class2func(path):
    ''' Convert a path such as 'Landroid/support/v4/app/ActivityCompat;'
        into a method string 'CLASS_Landroid_support_v4_app_ActivityCompat'
        so we can call d.CLASS_Landroid_support_v4_app_ActivityCompat.get_source()
    '''

    func = "CLASS_" + path.replace("/", "_").replace("$", "_").replace(";", "")
    return func

def method2func(method):
    return "METHOD_" + method.replace("/", "_").replace("[", "").replace("(",
            "").replace(")", "").replace(";", "")

def classmethod2func(class_, method_):
    '''Convert two strings such as "Lcom/mwr/example/sieve/AddEntryActivity;" and "onCreate"
       into a string "CLASS_Lcom_example_sieve_AddEntryActivity.METHOD_onCreate"
       so we can access d.CLASS_Lcom_example_sieve_AddEntryActivity.METHOD_onCreate.XREFfrom
    '''

    return "%s.%s" % (class2func(class_), method2func(method_))

def classmethod2display(class_, method_, descriptor_):
    '''Convert two strings such as "Lcom/mwr/example/sieve/AddEntryActivity;" and "onCreate"
    into a beautiful :) string to display Xrefs:
    "Lcom/mwr/example/sieve/AddEntryActivity; -> onCreate"
    '''

    return "%s -> %s ( %s )" % (class_, method_, descriptor_)

def display2classmethod(display):
    '''Opposite of classmethod2display.
    '''

    L = display.split(" -> ")
    return (L[0], L[1])

def classdot2func(path):
    ''' Convert a path such as 'android.support.v4.app.ActivityCompat'
        into a method string 'CLASS_Landroid_support_v4_app_ActivityCompat'
        so we can call d.CLASS_Landroid_support_v4_app_ActivityCompat.get_source()
    '''

    func = "CLASS_L" + path.replace(".", "_").replace("$", "_")
    return func

def classdot2class(path):
    ''' Convert a path such as 'android.support.v4.app.ActivityCompat'
        into a string 'Landroid/support/v4/app/ActivityCompat'
        so we can change name of a class by d.CLASS_Landroid_support_v4_app_ActivityCompat.set_name(new_name)
    '''
    if path[0] == 'L' and path[-1] == ';':
        print "WARNING: %s already a Lclass; name" % path
        return path

    new_name = 'L' + path.replace('.', '/') + ';'
    return new_name

def proto2methodprotofunc(proto):
    '''Convert a prototype such as 'Ljava/lang/String;'
       into a string 'Ljava_lang_String" so we can append that to the
       'METHOD_myMethod' if its export python name contains the prototype
    '''
    return proto.replace(' ','').replace('(','').replace('[','').replace(')','').replace('/','_').replace(';','')
