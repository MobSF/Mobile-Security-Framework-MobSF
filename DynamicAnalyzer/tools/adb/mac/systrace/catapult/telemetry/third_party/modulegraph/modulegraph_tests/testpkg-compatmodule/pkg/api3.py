import http.client

def div(a, b):
    try:
        return a/b

    except ZeroDivisionError as exc:
        return None

class MyClass (object, metaclass=type):
    pass
