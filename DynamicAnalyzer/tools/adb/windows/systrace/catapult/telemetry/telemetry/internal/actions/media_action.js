// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.


// This file provides common functions for media actions.
window.__findMediaElements = function(selector) {
  // Returns elements matching the selector, otherwise returns the first video
  // or audio tag element that can be found.
  // If selector == 'all', returns all media elements.
  if (selector == 'all') {
    return document.querySelectorAll('video, audio');
  } else if (selector) {
    return document.querySelectorAll(selector);
  } else {
    var media = document.getElementsByTagName('video');
    if (media.length > 0) {
      return [media[0]];
    } else {
      media = document.getElementsByTagName('audio');
      if (media.length > 0) {
        return [media[0]];
      }
    }
  }
  console.error('Could not find any media elements matching: ' + selector);
  return [];
};

window.__hasEventCompleted = function(selector, event_name) {
  // Return true if the event_name fired for media satisfying the selector.
  var mediaElements = window.__findMediaElements(selector);
  for (var i = 0; i < mediaElements.length; i++) {
    if (!mediaElements[i][event_name + '_completed'])
      return false;
  }
  return true;
};

window.__registerHTML5ErrorEvents = function(element) {
  // Listens to HTML5 media errors.
  function onError(e) {
    window.__error = 'Media error: ' + e.type + ', code:' + e.target.error.code;
    throw new Error(window.__error);
  }
  element.addEventListener('error', onError);
  element.addEventListener('abort', onError);
};

window.__registerHTML5EventCompleted = function(element, event_name) {
  // Logs |even_name| on element when completed.
  var logEventHappened = function(e) {
    element[e.type + '_completed'] = true;
    element.removeEventListener(event_name, logEventHappened);
  }
  element.addEventListener(event_name, logEventHappened);
};

window.__error = null;
