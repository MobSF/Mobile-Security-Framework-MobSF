"""
This file contains enums used to define static source code analysis rules.

Match - It is an Enum used to run proper rule detection.
    1. single_regex - if re.findall(regex1, input)
    2. regex_and - if re.findall(regex1, input) and re.findall(regex2, input)
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
    12. string_and_not - if ((string1 in input) and (string2 not in input))

MatchType - It is an Enum used to define match type.
   1. string
   2. regex

Level - It defines level of the rule.
   1. high - Rule has a high security impact.
             It will decrease security result by 15 points.
   2. warning - Rule warns about potencial security leaks.
                It will decrease security result by 10 points.
   3. info - Rule informs about best practice in some posible cases.
             It won't decrease security result.
   4. good - Rule increase app security.
             It will increase security result by 5 points.

InputCase - It is an Enum that defines how we should match pattern.
   1. upper
   2. lower
   3. exact
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
    string_and_not = 12


class MatchType(Enum):
    string = 'string'
    regex = 'regex'


class Level(Enum):
    high = 'high'
    warning = 'warning'
    info = 'info'
    good = 'good'


class InputCase(Enum):
    upper = 'upper'
    lower = 'lower'
    exact = 'exact'
