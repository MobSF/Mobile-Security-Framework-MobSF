# Copyright 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

UA_TYPE_MAPPING = {
  'desktop':
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) '
      'AppleWebKit/537.36 (KHTML, like Gecko) '
      'Chrome/40.0.2194.2 Safari/537.36',
  'mobile':
      'Mozilla/5.0 (Linux; Android 4.0.4; Galaxy Nexus Build/IMM76B) '
      'AppleWebKit/535.36 (KHTML, like Gecko) Chrome/40.0.2194.2 Mobile '
      'Safari/535.36',
  'tablet':
      'Mozilla/5.0 (Linux; Android 4.0.4; Galaxy Nexus 7 Build/IMM76B) '
      'AppleWebKit/535.36 (KHTML, like Gecko) Chrome/40.0.2194.2 '
      'Safari/535.36',
  'tablet_10_inch':
      'Mozilla/5.0 (Linux; Android 4.0.4; Galaxy Nexus 10 Build/IMM76B) '
      'AppleWebKit/535.36 (KHTML, like Gecko) Chrome/40.0.2194.2 '
      'Safari/535.36',
}


def GetChromeUserAgentArgumentFromType(user_agent_type):
  """Returns a chrome user agent based on a user agent type.
  This is derived from:
  https://developers.google.com/chrome/mobile/docs/user-agent
  """
  if user_agent_type:
    return ['--user-agent=%s' % UA_TYPE_MAPPING[user_agent_type]]
  return []

def GetChromeUserAgentDictFromType(user_agent_type):
  if user_agent_type:
    return {'userAgent': UA_TYPE_MAPPING[user_agent_type]}
  return {}
