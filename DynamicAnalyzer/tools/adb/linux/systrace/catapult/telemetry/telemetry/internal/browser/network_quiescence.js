// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

'use strict';

/**
 * @fileoverview This file provides a JavaScript helper function that
 * determines when network quiescence has been reached based on the time since
 * the last resource was received.
 */
(function() {

  // Make executing this code idempotent.
  if (window.__telemetry_testHasReachedNetworkQuiescence) {
    return;
  }

  // Some benchmarks patch window.performance to make it deterministic.
  // Save the original performance object before it is patched.
  var real_performance = window.performance;

  // Set the Resource Timing interface functions that will be used below
  // to use whatever version is available currently regardless of vendor
  // prefix.
  real_performance.clearResourceTimings =
      (real_performance.clearResourceTimings     ||
       real_performance.mozClearResourceTimings  ||
       real_performance.msClearResourceTimings   ||
       real_performance.oClearResourceTimings    ||
       real_performance.webkitClearResourceTimings);

  real_performance.getEntriesByType =
      (real_performance.getEntriesByType     ||
       real_performance.mozGetEntriesByType  ||
       real_performance.msGetEntriesByType   ||
       real_performance.oGetEntriesByType    ||
       real_performance.webkitGetEntriesByType);

  // This variable will available to the function below and it will be
  // persistent across different function calls. It stores the last
  // entry in the list of PerformanceResourceTiming objects returned by
  // real_performance.getEntriesByType('resource').
  //
  // The reason for doing it this way is because the buffer for
  // PerformanceResourceTiming objects has a limit, and once it's full,
  // new entries are not added. We're only interested in the last entry,
  // so we can clear new entries when they're added.
  var lastEntry = null;

  // True when no resource has been loaded from the network for
  //|QUIESCENCE_TIMEOUT_MS| milliseconds. This value is sticky.
  var hasReachedQuiesence = false;

  // Time to wait before declaring network quiescence in milliseconds.
  var QUIESCENCE_TIMEOUT_MS = 2000;

  /**
   * This method uses the Resource Timing interface, which is described at
   * http://www.w3.org/TR/resource-timing/. It determines whether the time
   * since lodading any resources such as images and script files (including
   * resources requested via XMLHttpRequest) has exceeded a threshold defined
   # by |QUIESCENCE_TIMEOUT_MS|.
   *
   * @return {boolean} True if the time since either the load event, or the last
   *   resource was received after the load event exceeds the aforementioned
   *   threshold. This state is sticky, so once this function returns true for a
   *   given page, it will always return true.
   */
  window.__telemetry_testHasReachedNetworkQuiescence = function() {
    if (hasReachedQuiesence) {
      return true;
    }

    if (window.document.readyState !== 'complete') {
      return false;
    }

    var resourceTimings = real_performance.getEntriesByType('resource');
    if (resourceTimings.length > 0) {
      lastEntry = resourceTimings.pop();
      real_performance.clearResourceTimings();
    }

    // The times for performance.now() and in the PerformanceResourceTiming
    // objects are all in milliseconds since performance.timing.navigationStart,
    // so we must also get load time in the same terms.
    var timing = real_performance.timing;
    var loadTime = timing.loadEventEnd - timing.navigationStart;
    var lastResponseTimeMs = 0;

    // If there have been no resource timing entries, or the last entry was
    // before the load event, then use the time since the load event.
    if (!lastEntry || lastEntry.responseEnd < loadTime) {
      lastResponseTimeMs = real_performance.now() - loadTime;
    } else {
      lastResponseTimeMs = real_performance.now() - lastEntry.responseEnd;
    }

    if (lastResponseTimeMs >= QUIESCENCE_TIMEOUT_MS) {
      hasReachedQuiesence = true;
    }

    return hasReachedQuiesence;
  }

})();
