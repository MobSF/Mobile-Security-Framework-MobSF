from abc import ABC, abstractclassmethod
import re
import logging

logger = logging.getLogger(__name__)


class MatchStrategy(ABC):

    @abstractclassmethod
    def perform_search(self, content, rule, perms):
        """
        Search for instance of match in content
        """


class single_regex(MatchStrategy):

    def perform_search(self, content, rule, perms):
        found = False
        if re.findall(rule['match'], content):
            found = True
        return found


class regex_and(MatchStrategy):
    def perform_search(self, content, rule, perms):
        found = True
        # This check is used because if you only pass a str rather than a list,
        # Python will iterate through the str without raising an exception
        if isinstance(rule['match'], str):
            logger.debug("wrong regex type, switching to single regex")
            return single_regex().perform_search(content, rule, perms)
        for regex in rule['match']:
            if bool(re.findall(regex, content)) is False:
                found = False
                break
        return found


class regex_or(MatchStrategy):
    def perform_search(self, content, rule, perms):
        found = False
        if isinstance(rule['match'], str):
            logger.debug("wrong regex type, switching to single regex")
            return single_regex().perform_search(content, rule, perms)
        for regex in rule['match']:
            if re.findall(regex, content):
                found = True
                break
        return found


class string_and(MatchStrategy):
    def perform_search(self, content, rule, perms):
        and_match_str = True
        for match in rule['match']:
            if (match in content) is False:
                and_match_str = False
                break
        return and_match_str
