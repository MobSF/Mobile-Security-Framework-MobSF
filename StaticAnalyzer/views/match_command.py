from StaticAnalyzer.views import match_strategy

import logging

logger = logging.getLogger(__name__)


class MatchCommand:

    def __init__(self):
        self.patterns = {}

    def find_match(self, pattern_name, content, rule, perms):
        if pattern_name not in self.patterns:
            logger.debug('adding %s in the pool of patterns', pattern_name)
            pattern_class = getattr(match_strategy, pattern_name)
            self.patterns[pattern_name] = pattern_class()
        return self.patterns[pattern_name].perform_search(content, rule, perms)
