// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file provides the DragAction object, which performs drag on a page
// using given start and end positions:
//   1. var action = new __DragAction(callback)
//   2. action.start(drag_options)
'use strict';

(function() {
  function DragGestureOptions(opt_options) {
    this.element_ = opt_options.element;
    this.left_start_ratio_ = opt_options.left_start_ratio;
    this.top_start_ratio_ = opt_options.top_start_ratio;
    this.left_end_ratio_ = opt_options.left_end_ratio;
    this.top_end_ratio_ = opt_options.top_end_ratio;
    this.speed_ = opt_options.speed;
    this.gesture_source_type_ = opt_options.gesture_source_type;
  }

  function supportedByBrowser() {
    return !!(window.chrome &&
              chrome.gpuBenchmarking &&
              chrome.gpuBenchmarking.smoothDrag &&
              chrome.gpuBenchmarking.visualViewportHeight &&
              chrome.gpuBenchmarking.visualViewportWidth);
  }

  // This class performs drag action using given start and end positions,
  // by a single drag gesture.
  function DragAction(opt_callback) {
    this.beginMeasuringHook = function() {};
    this.endMeasuringHook = function() {};

    this.callback_ = opt_callback;
  }

  DragAction.prototype.start = function(opt_options) {
    this.options_ = new DragGestureOptions(opt_options);
    requestAnimationFrame(this.startGesture_.bind(this));
  };

  DragAction.prototype.startGesture_ = function() {
    this.beginMeasuringHook();

    var rect = __GestureCommon_GetBoundingVisibleRect(this.options_.element_);
    var start_left =
        rect.left + (rect.width * this.options_.left_start_ratio_);
    var start_top =
        rect.top + (rect.height * this.options_.top_start_ratio_);
    var end_left =
        rect.left + (rect.width * this.options_.left_end_ratio_);
    var end_top =
        rect.top + (rect.height * this.options_.top_end_ratio_);
    chrome.gpuBenchmarking.smoothDrag(
        start_left, start_top, end_left, end_top,
        this.onGestureComplete_.bind(this), this.options_.gesture_source_type_,
        this.options_.speed_);
  };

  DragAction.prototype.onGestureComplete_ = function() {
    this.endMeasuringHook();

    // We're done.
    if (this.callback_)
      this.callback_();
  };

  window.__DragAction = DragAction;
  window.__DragAction_SupportedByBrowser = supportedByBrowser;
})();
