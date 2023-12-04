# !/usr/bin/python3
# -*- coding: utf-8 -*-
# Copyright (C) 2023 Sarp Cyber Security - All Rights Reserved
# Unauthorized copying of this file, via any medium is strictly prohibited
# Proprietary and confidential


import json
import os
import shutil
import mimetypes
import logging
import time

import requests
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management.base import BaseCommand
from django.http import HttpRequest
from django.utils.datastructures import MultiValueDict

from mobsf.MobSF import settings
from mobsf.MobSF.views.api.api_static_analysis import api_scan, api_upload

"""
Following variables must be set in the settings py
APPLICATION_MAIN_BUCKET = ''
SERVICE_KEY = ''
"""


class Command(BaseCommand):
    help = 'Daemon that runs for scan mobile applications'
    headers = {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
               'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.7',
               'Accept-Language': 'en-us,en;q=0.5',
               'User-Agent': "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
               "Authorization": os.environ.get("MOBSF_API_KEY"),
               "X-Mobsf-Api-Key": os.environ.get("MOBSF_API_KEY")}

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)

    @staticmethod
    def call_api_scan(params):
        fake_request = HttpRequest()
        fake_request.method = 'POST'
        fake_request.POST['scan_type'] = params['scan_type']
        fake_request.POST['hash'] = params['hash']
        fake_request.POST['file_name'] = params['file_name']
        response = api_scan(fake_request)
        return response

    @staticmethod
    def get_mime_type(file_path):
        mime_type, encoding = mimetypes.guess_type(file_path)
        return mime_type

    @staticmethod
    def move_file_to_error_folder(file_path: str, error_folder: str, error: str):
        file_name = os.path.basename(file_path)
        unprocessed_file = os.path.join(error_folder, file_name)
        shutil.move(file_path, unprocessed_file)
        info_file = os.path.join(error_folder, f"{file_name}.info")
        shutil.move(f"{file_path}.info", info_file)
        error_file = os.path.join(error_folder, file_name + ".error")
        with open(error_file, 'w') as f:
            f.write(str(error))

    @staticmethod
    def move_file_processed_folder(file_path: str, processed_folder: str):
        file_name = os.path.basename(file_path)
        shutil.move(file_path, os.path.join(processed_folder, file_name))
        info_file_name = f"{file_name}.info"
        shutil.move(f"{file_path}.info", os.path.join(processed_folder, info_file_name))
        os.remove(f"{file_path}.mkr")

    @staticmethod
    def send_scan_completed_signal(file_params):
        service_key = settings.SERVICE_KEY
        url = "https://platform.socradar.com/api/mobile_mole/scan/completed?"
        url += f"hash={file_params['hash']}&"
        url += f"scan_type={file_params['scan_type']}&"
        url += f"file_name={file_params['file_name']}&"
        url += f"mobile_app_id={file_params['mobile_app_id']}&"
        url += f"company_id={file_params['company_id']}"
        url += f"&key={service_key}"
        response = requests.get(url, timeout=30)
        return json.loads(response.text)

    @staticmethod
    def fake_request(file_path=None):
        file_name = os.path.basename(file_path)
        mime_type = Command.get_mime_type(file_path)
        file_data = open(file_path, 'rb').read()
        uploaded_file = SimpleUploadedFile(file_name, file_data, content_type=mime_type)
        request = HttpRequest()
        request.method = 'POST'
        request.FILES = MultiValueDict({'file': [uploaded_file]})
        boundary = '----WebKitFormBoundary'
        request.META['CONTENT_TYPE'] = f'multipart/form-data; boundary={boundary}'
        return request

    def handle(self, *args, **kwargs):
        application_main_bucket = settings.APPLICATION_MAIN_BUCKET
        uploaded_folder = os.path.join(application_main_bucket, "uploaded")
        error_folder = os.path.join(application_main_bucket, "error")
        processed_folder = os.path.join(application_main_bucket, "processed")
        os.makedirs(uploaded_folder, exist_ok=True)
        os.makedirs(error_folder, exist_ok=True)
        os.makedirs(processed_folder, exist_ok=True)
        while True:
            file_list = os.listdir(uploaded_folder)
            if len(file_list) < 0:
                self.logger.info(f"There is no new uploaded mobile app file.")
                continue
            else:
                self.logger.info(f"There is new {len(file_list)} new app to scan. Processing")
            for file in file_list:
                self.logger.info(f"{file} is processing.")
                app_file_mkr = os.path.join(uploaded_folder, file + ".mkr")
                is_mkr_exists = os.path.isfile(app_file_mkr)
                is_info_file_exists = os.path.isfile(os.path.join(uploaded_folder, file + ".info"))
                if is_mkr_exists and is_info_file_exists:
                    print(f"Found file to process {file}")
                    file_path = os.path.join(uploaded_folder, file)
                    fake_req = Command.fake_request(file_path=file_path)
                    upload_res = api_upload(fake_req)
                    if upload_res.status_code == 200:
                        info_file = file_path + ".info"
                        app_info_content = {}
                        with open(info_file, 'r') as f:
                            app_info_content = json.load(f)
                        file_params = json.loads(upload_res.content)
                        response = Command.call_api_scan(file_params)
                        if response.status_code != 200:
                            Command.move_file_to_error_folder(os.path.join(uploaded_folder, file), error_folder, response.content)
                        else:
                            app_info_content.update(file_params)
                            platform_resp = Command.send_scan_completed_signal(app_info_content)
                            if platform_resp["response_code"] == 200:
                                Command.move_file_processed_folder(os.path.join(uploaded_folder, file), processed_folder)
                            # else:
                            #     Command.move_file_to_error_folder(os.path.join(uploaded_folder, file), error_folder, platform_resp["message"])
                    else:
                        Command.move_file_to_error_folder(os.path.join(uploaded_folder, file), error_folder, "File params could not be created")
                else:
                    self.logger.info(f".mkr .info file could not identified for {file}")

            self.logger.info(f"Uploaded Mobile applications finished now sleep 1 hour.")
            time.sleep(60 * 60)
