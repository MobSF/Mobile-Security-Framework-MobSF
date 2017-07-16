# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Provides functionality to interact with UI elements of an Android app."""

import collections
import re
from xml.etree import ElementTree as element_tree

from devil.android import decorators
from devil.android import device_temp_file
from devil.utils import geometry
from devil.utils import timeout_retry

_DEFAULT_SHORT_TIMEOUT = 10
_DEFAULT_SHORT_RETRIES = 3
_DEFAULT_LONG_TIMEOUT = 30
_DEFAULT_LONG_RETRIES = 0

# Parse rectangle bounds given as: '[left,top][right,bottom]'.
_RE_BOUNDS = re.compile(
    r'\[(?P<left>\d+),(?P<top>\d+)\]\[(?P<right>\d+),(?P<bottom>\d+)\]')


class _UiNode(object):

  def __init__(self, device, xml_node, package=None):
    """Object to interact with a UI node from an xml snapshot.

    Note: there is usually no need to call this constructor directly. Instead,
    use an AppUi object (below) to grab an xml screenshot from a device and
    find nodes in it.

    Args:
      device: A device_utils.DeviceUtils instance.
      xml_node: An ElementTree instance of the node to interact with.
      package: An optional package name for the app owning this node.
    """
    self._device = device
    self._xml_node = xml_node
    self._package = package

  def _GetAttribute(self, key):
    """Get the value of an attribute of this node."""
    return self._xml_node.attrib.get(key)

  @property
  def bounds(self):
    """Get a rectangle with the bounds of this UI node.

    Returns:
      A geometry.Rectangle instance.
    """
    d = _RE_BOUNDS.match(self._GetAttribute('bounds')).groupdict()
    return geometry.Rectangle.FromDict({k: int(v) for k, v in d.iteritems()})

  def Tap(self, point=None, dp_units=False):
    """Send a tap event to the UI node.

    Args:
      point: An optional geometry.Point instance indicating the location to
        tap, relative to the bounds of the UI node, i.e. (0, 0) taps the
        top-left corner. If ommited, the center of the node is tapped.
      dp_units: If True, indicates that the coordinates of the point are given
        in device-independent pixels; otherwise they are assumed to be "real"
        pixels. This option has no effect when the point is ommited.
    """
    if point is None:
      point = self.bounds.center
    else:
      if dp_units:
        point = (float(self._device.pixel_density) / 160) * point
      point += self.bounds.top_left

    x, y = (str(int(v)) for v in point)
    self._device.RunShellCommand(['input', 'tap', x, y], check_return=True)

  def Dump(self):
    """Get a brief summary of the child nodes that can be found on this node.

    Returns:
      A list of lines that can be logged or otherwise printed.
    """
    summary = collections.defaultdict(set)
    for node in self._xml_node.iter():
      package = node.get('package') or '(no package)'
      label = node.get('resource-id') or '(no id)'
      text = node.get('text')
      if text:
        label = '%s[%r]' % (label, text)
      summary[package].add(label)
    lines = []
    for package, labels in sorted(summary.iteritems()):
      lines.append('- %s:' % package)
      for label in sorted(labels):
        lines.append('  - %s' % label)
    return lines

  def __getitem__(self, key):
    """Retrieve a child of this node by its index.

    Args:
      key: An integer with the index of the child to retrieve.
    Returns:
      A UI node instance of the selected child.
    Raises:
      IndexError if the index is out of range.
    """
    return type(self)(self._device, self._xml_node[key], package=self._package)

  def _Find(self, **kwargs):
    """Find the first descendant node that matches a given criteria.

    Note: clients would usually call AppUi.GetUiNode or AppUi.WaitForUiNode
    instead.

    For example:

      app = app_ui.AppUi(device, package='org.my.app')
      app.GetUiNode(resource_id='some_element', text='hello')

    would retrieve the first matching node with both of the xml attributes:

      resource-id='org.my.app:id/some_element'
      text='hello'

    As the example shows, if given and needed, the value of the resource_id key
    is auto-completed with the package name specified in the AppUi constructor.

    Args:
      Arguments are specified as key-value pairs, where keys correnspond to
      attribute names in xml nodes (replacing any '-' with '_' to make them
      valid identifiers). At least one argument must be supplied, and arguments
      with a None value are ignored.
    Returns:
      A UI node instance of the first descendant node that matches ALL the
      given key-value criteria; or None if no such node is found.
    Raises:
      TypeError if no search arguments are provided.
    """
    matches_criteria = self._NodeMatcher(kwargs)
    for node in self._xml_node.iter():
      if matches_criteria(node):
        return type(self)(self._device, node, package=self._package)
    return None

  def _NodeMatcher(self, kwargs):
    # Auto-complete resource-id's using the package name if available.
    resource_id = kwargs.get('resource_id')
    if (resource_id is not None
        and self._package is not None
        and ':id/' not in resource_id):
      kwargs['resource_id'] = '%s:id/%s' % (self._package, resource_id)

    criteria = [(k.replace('_', '-'), v)
                for k, v in kwargs.iteritems()
                if v is not None]
    if not criteria:
      raise TypeError('At least one search criteria should be specified')
    return lambda node: all(node.get(k) == v for k, v in criteria)


class AppUi(object):
  # timeout and retry arguments appear unused, but are handled by decorator.
  # pylint: disable=unused-argument

  def __init__(self, device, package=None):
    """Object to interact with the UI of an Android app.

    Args:
      device: A device_utils.DeviceUtils instance.
      package: An optional package name for the app.
    """
    self._device = device
    self._package = package

  @property
  def package(self):
    return self._package

  @decorators.WithTimeoutAndRetriesDefaults(_DEFAULT_SHORT_TIMEOUT,
                                            _DEFAULT_SHORT_RETRIES)
  def _GetRootUiNode(self, timeout=None, retries=None):
    """Get a node pointing to the root of the UI nodes on screen.

    Note: This is currently implemented via adb calls to uiatomator and it
    is *slow*, ~2 secs per call. Do not rely on low-level implementation
    details that may change in the future.

    TODO(crbug.com/567217): Swap to a more efficient implementation.

    Args:
      timeout: A number of seconds to wait for the uiautomator dump.
      retries: Number of times to retry if the adb command fails.
    Returns:
      A UI node instance pointing to the root of the xml screenshot.
    """
    with device_temp_file.DeviceTempFile(self._device.adb) as dtemp:
      self._device.RunShellCommand(['uiautomator', 'dump', dtemp.name],
                                  check_return=True)
      xml_node = element_tree.fromstring(
          self._device.ReadFile(dtemp.name, force_pull=True))
    return _UiNode(self._device, xml_node, package=self._package)

  def ScreenDump(self):
    """Get a brief summary of the nodes that can be found on the screen.

    Returns:
      A list of lines that can be logged or otherwise printed.
    """
    return self._GetRootUiNode().Dump()

  def GetUiNode(self, **kwargs):
    """Get the first node found matching a specified criteria.

    Args:
      See _UiNode._Find.
    Returns:
      A UI node instance of the node if found, otherwise None.
    """
    # pylint: disable=protected-access
    return self._GetRootUiNode()._Find(**kwargs)

  @decorators.WithTimeoutAndRetriesDefaults(_DEFAULT_LONG_TIMEOUT,
                                            _DEFAULT_LONG_RETRIES)
  def WaitForUiNode(self, timeout=None, retries=None, **kwargs):
    """Wait for a node matching a given criteria to appear on the screen.

    Args:
      timeout: A number of seconds to wait for the matching node to appear.
      retries: Number of times to retry in case of adb command errors.
      For other args, to specify the search criteria, see _UiNode._Find.
    Returns:
      The UI node instance found.
    Raises:
      device_errors.CommandTimeoutError if the node is not found before the
      timeout.
    """
    def node_found():
      return self.GetUiNode(**kwargs)

    return timeout_retry.WaitFor(node_found)
