WebPageReplay Rule Language
===========================

WebPageReplay rules allows developers to customize record/replay handling.

Motiviation
-----------

Web sites often require custom replay logic, e.g.:

  1. The recording uploads various metrics/logs to:

        http://example.com/gen_204?emsg=foo

     but, during replay, it uploads different parameters:

        http://example.com/gen_204?emsg=bar

     so (as-is) our replay fails.  We want "*/gen_204" to always respond
     "HTTP 204 No Change".

  2. The recording fetches data from one server:

        http://mirrorA.example.com/stuff

     but replay selects a different server:

        http://mirrorB.example.com/stuff

     which breaks replay.  We want "mirror*.example.com/stuff" to be equivalent.

  3. The recorded URL + response contains a UID, e.g.:

        http://example.com?q=foo  -->  "you sent foo."

     but the replay asks for:

        http://example.com?q=bar  -->  replay error!

     We want it to reply "you sent bar."

We could hack all the above rules into the code, but that can''t be (cleanly) extended or open sourced.

Instead, we want a simple config file of "predicate --> action" rules.


Format
------

The JSON-formatted rule file is specified on the command line:

    replay.py ... --rules_path my_rules ...

The rules file must contain an array of single-item objects, e.g.:

    [{"comment": "ignore me"},
     {"LogUrl": {"url": "example\\.com/logme.*"}},
     {"LogUrl": {"url": "example\\.com/someotherpath"}}
    ]

All "comment" items are ignored and support arbitrary values, e.g., a string
or commented-out rule(s).

All other items must specify a string TYPE key and object ARGS value, e.g.:

     {"LogUrl": {"url": "example\\.com/test", "stop": false}}

The default TYPE package is "rules" and the default rule_parser
"allowed_imports" is similarly restricted to only allow "rules" classes.

The TYPE implementation class must match the Rule API defined in
"rules/rule.py":

  class Rule(object):
    def IsType(self, rule_type_name): ...
    def ApplyRule(self, return_value, request, response): ...

The ARGS must match the rule-specific constructor, e.g.:

    class LogUrl(rule.Rule):
      def __init__(self, url, stop=False):
        self._url_re = re.compile(url)
        self._stop = stop
      ...

All rules of the same rule_type_name are chained together and applied in the
same order as they appear in the input JSON file.


Rules
-------

### rules.LogUrl:

If the url pattern matches then log the request URL.
