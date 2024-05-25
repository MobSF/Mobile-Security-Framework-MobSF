"""Chat GPT module for MobSF."""
import logging

import openai

from django.conf import settings

logger = logging.getLogger(__name__)


class ChatGPT:

    def __init__(self, api_key):
        self.gpt_client = openai.Client(api_key=api_key)
        self.gpt_model = settings.OPENAI_GPT_MODEL

    def get_available_models(self):
        models = set()
        for i in self.gpt_client.models.list():
            models.add(i.id)
        return models

    def chat(self, messages):
        """Chat with GPT."""
        try:
            import pdb; pdb.set_trace()
            response = self.gpt_client.chat.completions.create(
                messages=messages,
                temperature=0,
                model=self.gpt_model,
                max_tokens=100,
                n=1,
            )
            return response['choices'][0]['message']['content']
        except openai.APIConnectionError:
            logger.error('The server could not be reached')
        except openai.RateLimitError:
            logger.error('You\'ve hit the OpenAI API rate limit')
        except openai.NotFoundError:
            logger.error('The requested model %s is not available. Available models: %s', self.gpt_model, self.get_available_models())
        except openai.APIStatusError as e:
            logger.error('OpenAI API is returning an error')
            logger.error(e.status_code)
            logger.error(e.response)
        except Exception:
            logger.exception('Chat with GPT failed')
        return None
