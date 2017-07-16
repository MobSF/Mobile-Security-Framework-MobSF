// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

'use strict';

(function() {
  function SwipeGestureOptions(opt_options) {
    if (opt_options) {
      this.element_ = opt_options.element;
      this.left_start_ratio_ = opt_options.left_start_ratio;
      this.top_start_ratio_ = opt_options.top_start_ratio;
      this.direction_ = opt_options.direction;
      this.distance_ = opt_options.distance;
      this.speed_ = opt_options.speed;
    } else {
      this.element_ = document.body;
      this.left_start_ratio_ = 0.5;
      this.top_start_ratio_ = 0.5;
      this.direction_ = 'left';
      this.distance_ = 0;
      this.speed_ = 800;
    }
  }

  function supportedByBrowser() {
    return !!(window.chrome &&
              chrome.gpuBenchmarking &&
              chrome.gpuBenchmarking.swipe &&
              chrome.gpuBenchmarking.visualViewportHeight &&
              chrome.gpuBenchmarking.visualViewportWidth);
  }

  // This class swipes a page for a specified distance.
  function SwipeAction(opt_callback) {
    var self = this;

    this.beginMeasuringHook = function() {};
    this.endMeasuringHook = function() {};

    this.callback_ = opt_callback;
  }

  SwipeAction.prototype.start = function(opt_options) {
    this.options_ = new SwipeGestureOptions(opt_options);
    // Assign this.element_ here instead of constructor, because the constructor
    // ensures this method will be called after the document is loaded.
    this.element_ = this.options_.element_;
    requestAnimationFrame(this.startGesture_.bind(this));
  };

  SwipeAction.prototype.startGesture_ = function() {
    this.beginMeasuringHook();

    var rect = __GestureCommon_GetBoundingVisibleRect(this.options_.element_);
    var start_left =
        rect.left + rect.width * this.options_.left_start_ratio_;
    var start_top =
        rect.top + rect.height * this.options_.top_start_ratio_;
    chrome.gpuBenchmarking.swipe(this.options_.direction_,
                                 this.options_.distance_,
                                 this.onGestureComplete_.bind(this),
                                 start_left, start_top,
                                 this.options_.speed_);
  };

  SwipeAction.prototype.onGestureComplete_ = function() {
    this.endMeasuringHook();

    // We're done.
    if (this.callback_)
      this.callback_();
  };

  window.__SwipeAction = SwipeAction;
  window.__SwipeAction_SupportedByBrowser = supportedByBrowser;
})();
