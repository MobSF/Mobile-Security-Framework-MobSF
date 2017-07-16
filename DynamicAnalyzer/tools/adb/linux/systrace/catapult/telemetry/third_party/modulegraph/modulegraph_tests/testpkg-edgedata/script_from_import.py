from pkg import toplevel_existing
from pkg import toplevel_nonexisting

class MyClass:
    from pkg import toplevel_class_existing
    from pkg import toplevel_class_nonexisting

if a == b:
    from pkg import toplevel_conditional_existing
    from pkg import toplevel_conditional_nonexisting

    try:
        from pkg import toplevel_conditional_import_existing, toplevel_conditional_import_nonexisting
    except:
        from pkg import toplevel_conditional_import2_existing
        from pkg import toplevel_conditional_import2_nonexisting

try:
    from pkg import toplevel_import_existing, toplevel_import_nonexisting
except:
    from pkg import toplevel_import2_existing
    from pkg import toplevel_import2_nonexisting

def function():
    from pkg import function_existing, function_nonexisting

    class MyClass:
        from pkg import function_class_existing, function_class_nonexisting

    if a == b:
        from pkg import function_conditional_existing
        from pkg import function_conditional_nonexisting

        try:
            from pkg import function_conditional_import_existing
            from pkg import function_conditional_import_nonexisting
        except:
            from pkg import function_conditional_import2_existing
            from pkg import function_conditional_import2_nonexisting

    try:
        from pkg import function_import_existing
        from pkg import function_import_nonexisting
    except:
        from pkg import function_import2_existing
        from pkg import function_import2_nonexisting
