<!-- Copyright 2015 The Chromium Authors. All rights reserved.
     Use of this source code is governed by a BSD-style license that can be
     found in the LICENSE file.
-->
Systrace
========

Systrace relies on
[Trace-Viewer](https://github.com/catapult-project/catapult/blob/master/tracing/README.md)
to visualize the traces. The development of Trace-Viewer and Systrace is
decoupled by the systrace_trace_viewer.html file.
* The update_systrace_trace_viewer.py script generates
systrace_trace_viewer.html based on the Trace-Viewer code.
* Systrace visualizes the trace result based on systrace_trace_viewer.html.
* Systrace will auto update systrace_trace_viewer.html if
update_systrace_trace_viewer.py exists.
