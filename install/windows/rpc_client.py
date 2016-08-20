import configparser
import hashlib
import re
import subprocess
import sys
import os

from flask import Flask, request, redirect, url_for

from werkzeug.utils import secure_filename

app = Flask(__name__)

@app.route('/static_analyze/<string:sample>')
def static_analyze(sample):
    """Perform an static analysis on the sample and return the json"""

    # Check if param is a md5 to prevent attacks (we only use lower-case)
    if len(re.findall(r"([a-f\d]{32})", sample)) == 0:
        return "Wrong Input!"

    # Set params for execution of binskim
    binskim = app.config['binskimx64']
    command = "analyze"
    path = app.config['mobsf_samples'] + sample
    output_p = "-o"
    output_d = "C:\\Tools\\test.json"
    verbose = "-v"
    policy_p = "--config"
    policy_d = "default" # TODO(Other policies?)

    # Assemble
    params = [
            binskim,
            command,
            path,
            output_p, output_d,
            #verbose,
            policy_p, policy_d
        ]

    # Execute process
    p = subprocess.Popen(subprocess.list2cmdline(params))
    p.wait() # Wait for the process to finish..

    # Open the file and return the json
    f = open(output_d)
    return f.read()

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Upload a file."""
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit a empty part without filename
        if file.filename == '':
            flash('No file selected.')
            return redirect(request.url)
        if file:
            m = hashlib.md5()
            pos = file.tell() # Store pos
            test = file.read()
            # print(test) # Debug print
            m.update(test)
            file.seek(pos) # Restore pos
            file.save(os.path.join(app.config['mobsf_samples'], m.hexdigest()))
            return m.hexdigest()
    return '''
    <!doctype html>
    <title>Upload new Sample-File</title>
    <h1>Upload new Sample-File</h1>
    This should normaly be done via multipart post request.
    <form action="" method=post enctype=multipart/form-data>
      <p><input type=file name=file>
         <input type=submit value=Upload>
    </form>
    '''


if __name__ == '__main__':
    # Init configparser
    config = configparser.ConfigParser()
    config.read('C:\\MobSF\\Config\\config.txt')

    # Set the required config args in flask
    app.config['mobsf_dir'] = config['MobSF']['dir']
    app.config['mobsf_tools_dir'] = config['MobSF']['subdir_tools']
    app.config['mobsf_samples'] = config['MobSF']['subdir_samples']
    app.config['binskimx64'] = config['binskim']['file_x64']
    app.config['binskimx86'] = config['binskim']['file_x86']

    # Start the app
    app.run(host='0.0.0.0')
