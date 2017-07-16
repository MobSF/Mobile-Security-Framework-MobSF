#!/usr/bin/env python
# Copyright 2010 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import threading


class DaemonServer(object):
  """Base class which manages creation and cleanup of daemon style servers."""

  def __enter__(self):
    # TODO: Because of python's Global Interpreter Lock (GIL), the threads
    # will run on the same CPU. Consider using processes instead because
    # the components do not need to communicate with each other. On Linux,
    # "taskset" could be used to assign each process to specific CPU/core.
    # Of course, only bother with this if the processing speed is an issue.
    # Some related discussion: http://stackoverflow.com/questions/990102/python-
    # global-interpreter-lock-gil-workaround-on-multi-core-systems-using-tasks
    thread = threading.Thread(target=self.serve_forever)
    thread.daemon = True  # Python exits when no non-daemon threads are left.
    thread.start()
    return self

  def __exit__(self, unused_exc_type, unused_exc_val, unused_exc_tb):
    self.cleanup()
