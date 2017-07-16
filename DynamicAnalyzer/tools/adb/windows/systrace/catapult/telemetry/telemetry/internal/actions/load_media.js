// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

(function() {
  function loadMediaAndAwait(selector, event_to_await) {
    var mediaElements = window.__findMediaElements(selector);
    for (var i = 0; i < mediaElements.length; i++) {
      console.log('Listening for ' + event_to_await + ' on element: ' +
                  mediaElements[i].src);
      registerListeners(mediaElements[i], event_to_await);
      loadMediaElement(mediaElements[i]);
    }
  }

  function loadMediaElement(element) {
    if (element instanceof HTMLMediaElement) {
      element.load();
    } else {
      throw new Error('Can not load non media elements.');
    }
  }

  function registerListeners(element, event_to_await) {
    window.__registerHTML5ErrorEvents(element);
    window.__registerHTML5EventCompleted(element, event_to_await);
  }

  window.__loadMediaAndAwait = loadMediaAndAwait;
})();
