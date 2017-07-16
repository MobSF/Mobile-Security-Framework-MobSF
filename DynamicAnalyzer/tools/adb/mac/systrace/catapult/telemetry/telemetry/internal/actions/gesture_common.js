// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file provides common functionality for synthetic gesture actions.
'use strict';

(function() {

  // Make sure functions are injected only once.
  if (window.__GestureCommon_GetBoundingVisibleRect)
    return;

  // Returns the bounding rectangle wrt to the top-most document.
  function getBoundingRect(el) {
    var clientRect = el.getBoundingClientRect();
    var bound = { left: clientRect.left,
                  top: clientRect.top,
                  width: clientRect.width,
                  height: clientRect.height };

    var frame = el.ownerDocument.defaultView.frameElement;
    while (frame) {
      var frameBound = frame.getBoundingClientRect();
      // This computation doesn't account for more complex CSS transforms on the
      // frame (e.g. scaling or rotations).
      bound.left += frameBound.left;
      bound.top += frameBound.top;

      frame = frame.ownerDocument.frameElement;
    }
    return bound;
  }

  // TODO(ulan): Remove this function once
  // chrome.gpuBenchmarking.pageScaleFactor is available in reference builds.
  function getPageScaleFactor() {
    if (chrome.gpuBenchmarking.pageScaleFactor)
      return chrome.gpuBenchmarking.pageScaleFactor();
    return 1;
  }

  // Zoom-independent window height. See crbug.com/627123 for more details.
  function getWindowHeight() {
    return getPageScaleFactor() * chrome.gpuBenchmarking.visualViewportHeight();
  }

  // Zoom-independent window width. See crbug.com/627123 for more details.
  function getWindowWidth() {
    return getPageScaleFactor() * chrome.gpuBenchmarking.visualViewportWidth();
  }

  function clamp(min, value, max) {
    return Math.min(Math.max(min, value), max);
  }

  function getBoundingVisibleRect(el) {
    // Get the element bounding rect.
    var rect = getBoundingRect(el);

    // Get the window dimensions.
    var windowHeight = getWindowHeight();
    var windowWidth = getWindowWidth();

    // Then clip the rect to the screen size.
    rect.top = clamp(0, rect.top, windowHeight);
    rect.left = clamp(0, rect.left, windowWidth);
    rect.height = clamp(0, rect.height, windowHeight - rect.top);
    rect.width = clamp(0, rect.width, windowWidth - rect.left);

    return rect;
  }

  window.__GestureCommon_GetBoundingVisibleRect = getBoundingVisibleRect;
  window.__GestureCommon_GetWindowHeight = getWindowHeight;
  window.__GestureCommon_GetWindowWidth = getWindowWidth;
})();
