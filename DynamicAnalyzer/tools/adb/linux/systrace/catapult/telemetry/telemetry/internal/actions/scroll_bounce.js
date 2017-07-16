// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

'use strict';

(function() {
  function supportedByBrowser() {
    return !!(window.chrome &&
              chrome.gpuBenchmarking &&
              chrome.gpuBenchmarking.scrollBounce &&
              chrome.gpuBenchmarking.visualViewportHeight &&
              chrome.gpuBenchmarking.visualViewportWidth);
  }

  function ScrollBounceAction(opt_callback) {
    var self = this;

    this.beginMeasuringHook = function() {};
    this.endMeasuringHook = function() {};

    this.callback_ = opt_callback;
  }

  ScrollBounceAction.prototype.start = function(options) {
    this.options_ = options;
    // Assign this.element_ here instead of constructor, because the constructor
    // ensures this method will be called after the document is loaded.
    this.element_ = this.options_.element;
    requestAnimationFrame(this.startGesture_.bind(this));
  };

  ScrollBounceAction.prototype.startGesture_ = function() {
    this.beginMeasuringHook();

    var rect = __GestureCommon_GetBoundingVisibleRect(this.options_.element);
    var start_left =
        rect.left + rect.width * this.options_.left_start_ratio;
    var start_top =
        rect.top + rect.height * this.options_.top_start_ratio;
    chrome.gpuBenchmarking.scrollBounce(this.options_.direction,
                                        this.options_.distance,
                                        this.options_.overscroll,
                                        this.options_.repeat_count,
                                        this.onGestureComplete_.bind(this),
                                        start_left, start_top,
                                        this.options_.speed);
  };

  ScrollBounceAction.prototype.onGestureComplete_ = function() {
    this.endMeasuringHook();

    // We're done.
    if (this.callback_)
      this.callback_();
  };

  window.__ScrollBounceAction = ScrollBounceAction;
  window.__ScrollBounceAction_SupportedByBrowser = supportedByBrowser;
})();
