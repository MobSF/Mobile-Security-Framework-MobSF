"""Chat GPT prompts for MobSF."""
import logging
from pathlib import Path

from django.conf import settings

from mobsf.MobSF.chat_gpt import ChatGPT

logger = logging.getLogger(__name__)


class AndroidPrompts:

    def __init__(self):
        if not settings.OPENAI_API_KEY:
            return None
        self.gpt = ChatGPT(settings.OPENAI_API_KEY)

    def shared_object_identifier(self, shared_objects):
        """Identify shared object."""
        return None
        list_of_shared_objects = list(shared_objects)
        messages = [
            {'role': 'system', 'content': (
                'You are analyzing shared object files for Android applications as a Static Analyzer.'
                'You must always be truthful. Your responses should always be in json format.')},
            {'role': 'user', 'content': (
                f'Identify the SDK or Company from the shared object files is used in the following list. {list_of_shared_objects}.'
                'The resulting json response should be a list of dicts with two keys the file_name and company_name.'
                'The output should not be broken, and must be a valid json.')},
        ]
        return self.gpt.chat(messages)

    def package_name_identifier(self, source_dir):
        """Identify package name."""
        packages = set()
        src = Path(source_dir)
        for file_path in src.glob('**/*'):
            if file_path.is_file():
                pkg = file_path.parent.relative_to(src).as_posix().replace('/', '.')
                packages.add(pkg)
        print(packages)
        messages = [
            {'role': 'system', 'content': (
                'You are analyzing Android application java source code as a Static Analyzer.'
                'You must always be truthful. Your responses should always be in json format.')},
            {'role': 'user', 'content': (
                f'Identify the library or SDK name from the following package names. {source_dir}.'
                'Ignore the package name if you cannot identify the library or SDK name.'
                'The resulting json response should be a list of dict with the keys library_name and package_name.'
                'The output should not be broken, and must be a valid json.')},
        ]
        return self.gpt.chat(messages)