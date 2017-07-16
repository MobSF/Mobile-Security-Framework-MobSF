# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
from telemetry.internal.platform import gpu_info


class SystemInfo(object):
  """Provides low-level system information."""

  def __init__(self, model_name, gpu_dict):
    if (model_name == None) or (gpu_dict == None):
      raise Exception("Missing model_name or gpu_dict argument")
    self._model_name = model_name
    self._gpu = gpu_info.GPUInfo.FromDict(gpu_dict)

  @classmethod
  def FromDict(cls, attrs):
    """Constructs a SystemInfo from a dictionary of attributes.
       Attributes currently required to be present in the dictionary:

         model_name (string): a platform-dependent string
           describing the model of machine, or the empty string if not
           supported.
         gpu (object containing GPUInfo's required attributes)
    """
    return cls(attrs["model_name"], attrs["gpu"])

  @property
  def model_name(self):
    """A string describing the machine model.

       This is a highly platform-dependent value and not currently
       specified for any machine type aside from Macs. On Mac OS, this
       is the model identifier, reformatted slightly; for example,
       'MacBookPro 10.1'."""
    return self._model_name

  @property
  def gpu(self):
    """A GPUInfo object describing the graphics processor(s) on the system."""
    return self._gpu
