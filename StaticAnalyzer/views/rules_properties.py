"""
This file contains enums used to define static source code analysis rules.

Match is an Enum used to run proper rule detection.
    1. single_regex - if re.findall(regex1, input)
    2.regex_and - if re.findall(regex1, input) and re.findall(regex2, input)
    3. regex_or - if re.findall(regex1, input) or re.findall(regex2, input)
    4. single_string - if string1 in input
    5. string_and - if (string1 in input) and (string2 in input)
    6. string_or - if (string1 in input) or (string2 in input)
    7. string_and_or - if (string1 in input) and ((string_or1 in input)
                       or (string_or2 in input))
    8. string_or_and - if (string1 in input) or ((string_and1 in input)
                       and (string_and2 in input))
    9. regex_and_perm - if re.findall(regex, input) and (permission in
                        permission_list_from_manifest)
    10. string_and_perm - if (string1 in input)
                        and (permission in permission_list_from_manifest)
    11. string_or_and_perm - if ((string1 in input) or (string2 in input))
                           and (permission in permission_list_from_manifest)

MatchType is an Enum used to define match type.
   1. string
   2. regex
"""
from enum import Enum


class Match(Enum):
    single_regex = 1
    regex_and = 2
    regex_or = 3
    single_string = 4
    string_and = 5
    string_or = 6
    string_and_or = 7
    string_or_and = 8
    regex_and_perm = 9
    string_and_perm = 10
    string_or_and_perm = 11


class MatchType(Enum):
    string = 1
    regex = 2
