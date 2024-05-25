"""Chat GPT prompts for MobSF."""
import logging

from django.conf import settings

from mobsf.MobSF.chat_gpt import ChatGPT

logger = logging.getLogger(__name__)


class AndroidPrompts:

    def __init__(self):
        if not settings.OPENAI_API_KEY:
            return {}
        self.gpt = ChatGPT(settings.OPENAI_API_KEY)

    def shared_object_identifier(self, shared_objects):
        """Identify shared object."""
        # list_of_shared_objects = set()
        # for i in shared_objects:
        #     list_of_shared_objects.add(i['name'])
        list_of_shared_objects = shared_objects
        messages = [
            {'role': 'system', 'content': (
                'You are analyzing shared object files for Android applications as a Static Analyzer.'
                'You must always be truthful. Your responses should always be in json format.')},
            {'role': 'user', 'content': (
                f'Identify the shared object files is used in the following list. {list_of_shared_objects}')},
        ]
        return self.gpt.chat(messages)
