
import toplevel_existing
import toplevel_nonexisting

class MyClass:
    import toplevel_class_existing
    import toplevel_class_nonexisting

if a == b:
    import toplevel_conditional_existing
    import toplevel_conditional_nonexisting

    try:
        import toplevel_conditional_import_existing
        import toplevel_conditional_import_nonexisting
    except:
        import toplevel_conditional_import2_existing
        import toplevel_conditional_import2_nonexisting

try:
    import toplevel_import_existing
    import toplevel_import_nonexisting
except:
    import toplevel_import2_existing
    import toplevel_import2_nonexisting

def function():
    import function_existing
    import function_nonexisting

    class MyClass:
        import function_class_existing
        import function_class_nonexisting

    if a == b:
        import function_conditional_existing
        import function_conditional_nonexisting

        try:
            import function_conditional_import_existing
            import function_conditional_import_nonexisting
        except:
            import function_conditional_import2_existing
            import function_conditional_import2_nonexisting

    try:
        import function_import_existing
        import function_import_nonexisting
    except:
        import function_import2_existing
        import function_import2_nonexisting
