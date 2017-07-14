"""MobSF rpc_client for static windows app analysis."""
# pylint: disable=C0325,W0603,C0103
import os
from os.path import expanduser
import re
import subprocess
import configparser # pylint: disable-msg=E0401
import hashlib
import random
import string
import base64

from xmlrpc.server import SimpleXMLRPCServer # pylint: disable-msg=E0401

import rsa

config = None
challenge = None
pub_key = None

def _init_key():
    global pub_key
    pub_key = rsa.PublicKey.load_pkcs1(
        open(config['MobSF']['pub_key']).read()
    )

def _check_challenge(signature):
    signature = base64.b64decode(signature)
    try:
        rsa.verify(challenge.encode('utf-8'), signature, pub_key)
        print("[*] Challenge successfully verified.")
        _revoke_challenge()
    except rsa.pkcs1.VerificationError:
        print("[!] Received wrong signature for challenge.")
        raise Exception("Access Denied.")
    except (TypeError, AttributeError):
        print("[!] Challenge already unset.")
        raise Exception("Access Denied.")


def _revoke_challenge():
    """Revoke the challenge (to prevent replay attacks)"""
    global challenge
    challenge = None


def get_challenge():
    """Return an ascii challenge to validate authentication in _check_challenge."""
    global challenge
    # Not using os.urandom for Python 2/3 transfer errors
    challenge = ''.join(
        random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(256)
    )
    return "{}".format(challenge)


def test_challenge(signature):
    """Test function to check if rsa is working."""
    _check_challenge(signature)
    print("Check complete")
    return "OK!"

def upload_file(sample_file, signature):
    """Upload a file."""

    # Check challenge
    _check_challenge(signature)

    # Get md5
    md5 = hashlib.md5()
    md5.update(sample_file.data)

    # Save the file to disk
    with open(
        os.path.join(
            config['MobSF']['samples'],
            md5.hexdigest()
        ),
        "wb"
    ) as handle:
        handle.write(sample_file.data)

    # Return md5 as reference to the sample
    return md5.hexdigest()


def binskim(sample, signature):
    """Perform an static analysis on the sample and return the json"""

    # Check challenge
    _check_challenge(signature)

    # Check if param is a md5 to prevent attacks (we only use lower-case)
    if len(re.findall(r"([a-f\d]{32})", sample)) == 0:
        return "Wrong Input!"

    # Set params for execution of binskim
    binskim_path = config['binskim']['file_x64']
    command = "analyze"
    path = config['MobSF']['samples'] + sample
    output_p = "-o"
    output_d = config['MobSF']['samples'] + sample + "_binskim"
    verbose = "-v"
    policy_p = "--config"
    policy_d = "default"  # TODO(Other policies?)

    # Assemble
    params = [
        binskim_path,
        command,
        path,
        output_p, output_d,
        verbose,
        policy_p, policy_d
    ]

    # Execute process
    pipe = subprocess.Popen(subprocess.list2cmdline(params))
    pipe.wait()  # Wait for the process to finish..

    # Open the file and return the json
    out_file = open(output_d)
    return out_file.read()


def binscope(sample, signature):
    """Run binscope against an sample file."""

    # Check challenge
    _check_challenge(signature)

    # Set params for execution of binskim

    binscope_path = [config['binscope']['file']]
    target = [config['MobSF']['samples'] + sample]
    out_type = ["/Red", "/v"]
    output = ["/l", target[0] + "_binscope"]
    checks = [
        '/Checks', 'ATLVersionCheck',
        '/Checks', 'ATLVulnCheck',
        '/Checks', 'AppContainerCheck',
        '/Checks', 'CompilerVersionCheck',
        '/Checks', 'DBCheck',
        '/Checks', 'DefaultGSCookieCheck',
        '/Checks', 'ExecutableImportsCheck',
        '/Checks', 'FunctionPointersCheck',
        '/Checks', 'GSCheck',
        '/Checks', 'GSFriendlyInitCheck',
        '/Checks', 'GSFunctionSafeBuffersCheck',
        '/Checks', 'HighEntropyVACheck',
        '/Checks', 'NXCheck',
        '/Checks', 'RSA32Check',
        '/Checks', 'SafeSEHCheck',
        '/Checks', 'SharedSectionCheck',
        '/Checks', 'VB6Check',
        '/Checks', 'WXCheck',
    ]
    # Assemble
    params = (
        binscope_path +
        target +
        out_type +
        output +
        checks
    )

    # Execute process
    p = subprocess.Popen(subprocess.list2cmdline(params))
    p.wait()  # Wait for the process to finish..

    # Open the file and return the json
    f = open(output[1])
    return f.read()


if __name__ == '__main__':
    # Init configparser
    config = configparser.ConfigParser()

    config.read(expanduser("~") + "\\MobSF\\Config\\config.txt")

    _init_key()

    server = SimpleXMLRPCServer(("0.0.0.0", 8000))
    print("Listening on port 8000...")
    server.register_function(get_challenge, "get_challenge")
    server.register_function(test_challenge, "test_challenge")
    server.register_function(upload_file, "upload_file")
    server.register_function(binskim, "binskim")
    server.register_function(binscope, "binscope")
    server.serve_forever()
