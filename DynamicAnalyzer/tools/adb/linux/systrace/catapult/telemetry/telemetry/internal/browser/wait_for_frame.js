// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

'use strict';

/**
 * @fileoverview This file provides a JavaScript helper function that
 * determines whether at least one frame has passed since the first
 * call of this function with the given request id.
 */
(function() {

  // Make executing this code idempotent.
  if (window.__telemetry_testHasFramePassed) {
    return;
  }

  // A dictionary which tracks the number of requestAnimationFrame calls that
  // we are waiting on for the given request id.
  var pending_frames = {};

  window.__telemetry_testHasFramePassed = function(request_id) {
    // If we already have pending frames for the given request id, there is
    // no work to do, just return whether the pending frames have reached 0.
    if (pending_frames.hasOwnProperty(request_id)) {
      return pending_frames[request_id] == 0;
    }

    // We wait for two calls to requestAnimationFrame. When the first
    // requestAnimationFrame is called, we know that a frame is in the
    // pipeline. When the second requestAnimationFrame is called, we know that
    // the first frame has reached the screen.
    pending_frames[request_id] = 2;

    var wait_for_raf = function() {
      pending_frames[request_id]--;
      if (pending_frames[request_id] > 0) {
        window.requestAnimationFrame(wait_for_raf);
      }
    };

    window.requestAnimationFrame(wait_for_raf);
    return false;
  };
})();
