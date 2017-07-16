// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file performs actions on media elements.
(function() {
  function loopMedia(selector, loopCount) {
    // Loops media playback `loopCount` times.
    var mediaElements = window.__findMediaElements(selector);
    for (var i = 0; i < mediaElements.length; i++) {
      loop(mediaElements[i], loopCount);
    }
  }

  function loop(element, loopCount) {
    if (element instanceof HTMLMediaElement)
      loopHTML5Element(element, loopCount);
    else
      throw new Error('Can not play non HTML5 media elements.');
  }

  function loopHTML5Element(element, loopCount) {
    window.__registerHTML5ErrorEvents(element);
    element['loop_completed'] = false;
    var currentLoop = 0;
    var onLoop = function(e) {
      ++currentLoop;
      if (currentLoop == loopCount) {
        element.pause();
        element.removeEventListener('seeked', onLoop);
        element['loop_completed'] = true;
        // Dispatch endLoopEvent to mark end of looping.
        var endLoopEvent = document.createEvent('Event');
        endLoopEvent.initEvent('endLoop', false, false);
        element.dispatchEvent(endLoopEvent);
      }
    };

    element.addEventListener('seeked', onLoop);
    element.loop = true;

    // Dispatch willLoopEvent to measure loop time.
    var willLoopEvent = document.createEvent('Event');
    willLoopEvent.initEvent('willLoop', false, false);
    willLoopEvent.loopCount = loopCount;
    element.dispatchEvent(willLoopEvent);
    // Reset HTML5 player to start playback from beginning.
    element.load();
    element.play();
  }

  window.__loopMedia = loopMedia;
})();
