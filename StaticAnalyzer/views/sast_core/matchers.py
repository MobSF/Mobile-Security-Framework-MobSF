# -*- coding: utf_8 -*-
"""
Level - It defines level of the rule.

   1. high - A high security impact finding.
             It will decrease security score by 15 points.
   2. warning - A meduim impact security finding or warning.
                It will decrease security score by 10 points.
   3. info - Rule for catching informational findings.
             It will not decrease/increase security score.
   4. good - Rule that corresponds to a secure code finding.
             It will increase security score by 5 points.

InputCase - It is an Enum that defines how we should match pattern.
   1. upper
   2. lower
   3. exact

Match Types - Types of marchers supported
   a. SingleRegex - if re.findall(regex1, input)
   b. RegexAnd - if re.findall(regex1, input) and re.findall(regex2, input)
   c. RegexOr - if re.findall(regex1, input) or re.findall(regex2, input)
   d. SingleString - if string1 in input
   e. StringAnd - if (string1 in input) and (string2 in input)
   f. StringOr - if (string1 in input) or (string2 in input)
   g. StringAndOr -  if (string1 in input) and ((string2 in input)
                       or (string3 in input))
   h. StringAndPerm - if (string1 in input) and
                        (permission in permission_list_from_manifest)
   i. StringOrAndPerm - if ((string1 in input) or (string2 in input))
                           and (permission in permission_list_from_manifest)
   j. StringAndNot - if(string1 in input and string2 not in input)
"""
from abc import ABC, abstractclassmethod
from enum import Enum
import re
import logging

logger = logging.getLogger(__name__)


class Level(Enum):
    high = 'high'
    warning = 'warning'
    info = 'info'
    good = 'good'


class InputCase(Enum):
    upper = 'upper'
    lower = 'lower'
    exact = 'exact'


class MatchCommand:

    def __init__(self):
        self.patterns = {}

    def find_match(self, pattern_name, content, rule, perms):
        if pattern_name not in self.patterns:
            pattern_class = globals()[pattern_name]
            self.patterns[pattern_name] = pattern_class()
        return self.patterns[pattern_name].perform_search(content, rule, perms)


class MatchStrategy(ABC):

    @abstractclassmethod
    def perform_search(self, content, rule, perms):
        """Search for instance of match in content."""


class SingleRegex(MatchStrategy):

    def perform_search(self, content, rule, perms):
        return bool(re.findall(rule['match'], content))


class RegexAnd(MatchStrategy):
    def perform_search(self, content, rule, perms):
        # This check is used because if you only pass a str rather than a list,
        # Python will iterate through the str without raising an exception
        if isinstance(rule['match'], str):
            logger.debug('wrong regex type, switching to single regex')
            return SingleRegex().perform_search(content, rule, perms)
        for regex in rule['match']:
            if not bool(re.findall(regex, content)):
                return False
        return True


class RegexOr(MatchStrategy):
    def perform_search(self, content, rule, perms):
        if isinstance(rule['match'], str):
            logger.debug('wrong regex type, switching to single regex')
            return SingleRegex().perform_search(content, rule, perms)
        for regex in rule['match']:
            if re.findall(regex, content):
                return True
        return False


class SingleString(MatchStrategy):
    def perform_search(self, content, rule, perms):
        return rule['match'] in content


class StringAnd(MatchStrategy):
    def perform_search(self, content, rule, perms):
        for match in rule['match']:
            if match not in content:
                return False
        return True


class StringAndOr(MatchStrategy):
    def perform_search(self, content, rule, perms):
        string_or_stat = False
        or_list = rule['match'][1]
        for match in or_list:
            if match in content:
                string_or_stat = True
                break
        return string_or_stat and rule['match'][0] in content


class StringOrAndPerm(MatchStrategy):
    def perform_search(self, content, rule, perms):
        string_or_ps = False
        for match in rule['match']:
            if match in content:
                string_or_ps = True
                break
        return rule['perm'] in perms and string_or_ps


class StringAndPerm(MatchStrategy):
    def perform_search(self, content, rule, perms):
        return rule['perm'] in perms and rule['match'] in content


class StringOr(MatchStrategy):
    def perform_search(self, content, rule, perms):
        for match in rule['match']:
            if match in content:
                return True
        return False


class StringAndNot(MatchStrategy):
    def perform_search(self, content, rule, perms):
        return rule['match'][0] in content and rule['match'][1] not in content
