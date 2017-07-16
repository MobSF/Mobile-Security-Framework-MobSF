// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

'use strict';

(function() {

  function TapGestureOptions(opt_options) {
    if (opt_options) {
      this.element_ = opt_options.element;
      this.left_position_percentage_ = opt_options.left_position_percentage;
      this.top_position_percentage_ = opt_options.top_position_percentage;
      this.duration_ms_ = opt_options.duration_ms;
      this.gesture_source_type_ = opt_options.gesture_source_type;
    } else {
      this.element_ = document.body;
      this.left_position_percentage_ = 0.5;
      this.top_position_percentage_ = 0.5;
      this.duration_ms_ = 50;
      this.gesture_source_type_ = chrome.gpuBenchmarking.DEFAULT_INPUT;
    }
  }

  function supportedByBrowser() {
    return !!(window.chrome &&
              chrome.gpuBenchmarking &&
              chrome.gpuBenchmarking.tap &&
              chrome.gpuBenchmarking.visualViewportHeight &&
              chrome.gpuBenchmarking.visualViewportWidth);
  }

  function TapAction(opt_callback) {
    var self = this;

    this.beginMeasuringHook = function() {};
    this.endMeasuringHook = function() {};

    this.callback_ = opt_callback;
  }

  TapAction.prototype.start = function(opt_options) {
    this.options_ = new TapGestureOptions(opt_options);
    // Assign this.element_ here instead of constructor, because the constructor
    // ensures this method will be called after the document is loaded.
    this.element_ = this.options_.element_;

    this.beginMeasuringHook();

    var rect = __GestureCommon_GetBoundingVisibleRect(this.options_.element_);
    var position_left =
        rect.left + rect.width * this.options_.left_position_percentage_;
    var position_top =
        rect.top + rect.height * this.options_.top_position_percentage_;
    if (position_left < 0 ||
        position_left >= __GestureCommon_GetWindowWidth() ||
        position_top < 0 ||
        position_top >= __GestureCommon_GetWindowHeight()) {
      throw new Error('Tap position is off-screen');
    }
    chrome.gpuBenchmarking.tap(position_left, position_top,
                               this.onGestureComplete_.bind(this),
                               this.options_.duration_ms_,
                               this.options_.gesture_source_type_);
  };

  TapAction.prototype.onGestureComplete_ = function() {
    this.endMeasuringHook();

    // We're done.
    if (this.callback_)
      this.callback_();
  };

  window.__TapAction = TapAction;
  window.__TapAction_SupportedByBrowser = supportedByBrowser;
})();
