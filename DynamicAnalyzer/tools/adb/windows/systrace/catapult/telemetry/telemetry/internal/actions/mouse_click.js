// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

'use strict';

(function() {
  function MouseClickAction(opt_callback) {
    this.callback_ = opt_callback;
  }

  MouseClickAction.prototype.start = function(options) {
    this.click_(options.element);
  };

  MouseClickAction.prototype.click_ = function(element) {
    var triggerMouseEvent = this.triggerMouseEvent_;
    var callback = this.callback_;
    triggerMouseEvent(element, 'mouseover');
    triggerMouseEvent(element, 'mousedown');
    // ~100ms is typical for a mouse click's elapsed time.
    window.setTimeout(
      function() {
        triggerMouseEvent(element, 'mouseup');
        triggerMouseEvent(element, 'click', callback);
      }, 100);
  };

  MouseClickAction.prototype.triggerMouseEvent_ = function(
      node, eventType, callback) {
    var clickEvent = document.createEvent('MouseEvents');
    clickEvent.initEvent(eventType, true, true);
    node.dispatchEvent(clickEvent);
    if (callback) {
      window.setTimeout(callback, 0);
    }
  };

  window.__MouseClickAction = MouseClickAction;
})();
