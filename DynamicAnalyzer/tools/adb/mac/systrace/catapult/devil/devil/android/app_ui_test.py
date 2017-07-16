# Copyright 2015 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Unit tests for the app_ui module."""

import unittest
from xml.etree import ElementTree as element_tree

from devil import devil_env
from devil.android import app_ui
from devil.android import device_errors
from devil.utils import geometry

with devil_env.SysPath(devil_env.PYMOCK_PATH):
  import mock  # pylint: disable=import-error


MOCK_XML_LOADING = '''
<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node bounds="[0,50][1536,178]" content-desc="Loading"
      resource-id="com.example.app:id/spinner"/>
</hierarchy>
'''.strip()


MOCK_XML_LOADED = '''
<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node bounds="[0,50][1536,178]" content-desc=""
      resource-id="com.example.app:id/toolbar">
    <node bounds="[0,58][112,170]" content-desc="Open navigation drawer"/>
    <node bounds="[121,50][1536,178]"
        resource-id="com.example.app:id/actionbar_custom_view">
      <node bounds="[121,50][1424,178]"
          resource-id="com.example.app:id/actionbar_title" text="Primary"/>
      <node bounds="[1424,50][1536,178]" content-desc="Search"
          resource-id="com.example.app:id/actionbar_search_button"/>
    </node>
  </node>
  <node bounds="[0,178][576,1952]" resource-id="com.example.app:id/drawer">
    <node bounds="[0,178][144,1952]"
        resource-id="com.example.app:id/mini_drawer">
      <node bounds="[40,254][104,318]" resource-id="com.example.app:id/avatar"/>
      <node bounds="[16,354][128,466]" content-desc="Primary"
          resource-id="com.example.app:id/image_view"/>
      <node bounds="[16,466][128,578]" content-desc="Social"
          resource-id="com.example.app:id/image_view"/>
      <node bounds="[16,578][128,690]" content-desc="Promotions"
          resource-id="com.example.app:id/image_view"/>
    </node>
  </node>
</hierarchy>
'''.strip()


class UiAppTest(unittest.TestCase):

  def setUp(self):
    self.device = mock.Mock()
    self.device.pixel_density = 320  # Each dp pixel is 2 real pixels.
    self.app = app_ui.AppUi(self.device, package='com.example.app')
    self._setMockXmlScreenshots([MOCK_XML_LOADED])

  def _setMockXmlScreenshots(self, xml_docs):
    """Mock self.app._GetRootUiNode to load nodes from some test xml_docs.

    Each time the method is called it will return a UI node for each string
    given in |xml_docs|, or rise a time out error when the list is exhausted.
    """
    # pylint: disable=protected-access
    def get_mock_root_ui_node(value):
      if isinstance(value, Exception):
        raise value
      return app_ui._UiNode(
          self.device, element_tree.fromstring(value), self.app.package)

    xml_docs.append(device_errors.CommandTimeoutError('Timed out!'))

    self.app._GetRootUiNode = mock.Mock(
        side_effect=(get_mock_root_ui_node(doc) for doc in xml_docs))

  def assertNodeHasAttribs(self, node, attr):
    # pylint: disable=protected-access
    for key, value in attr.iteritems():
      self.assertEquals(node._GetAttribute(key), value)

  def assertTappedOnceAt(self, x, y):
    self.device.RunShellCommand.assert_called_once_with(
        ['input', 'tap', str(x), str(y)], check_return=True)

  def testFind_byText(self):
    node = self.app.GetUiNode(text='Primary')
    self.assertNodeHasAttribs(node, {
        'text': 'Primary',
        'content-desc': None,
        'resource-id': 'com.example.app:id/actionbar_title',
    })
    self.assertEquals(node.bounds, geometry.Rectangle([121, 50], [1424, 178]))

  def testFind_byContentDesc(self):
    node = self.app.GetUiNode(content_desc='Social')
    self.assertNodeHasAttribs(node, {
        'text': None,
        'content-desc': 'Social',
        'resource-id': 'com.example.app:id/image_view',
    })
    self.assertEquals(node.bounds, geometry.Rectangle([16, 466], [128, 578]))

  def testFind_byResourceId_autocompleted(self):
    node = self.app.GetUiNode(resource_id='image_view')
    self.assertNodeHasAttribs(node, {
        'content-desc': 'Primary',
        'resource-id': 'com.example.app:id/image_view',
    })

  def testFind_byResourceId_absolute(self):
    node = self.app.GetUiNode(resource_id='com.example.app:id/image_view')
    self.assertNodeHasAttribs(node, {
        'content-desc': 'Primary',
        'resource-id': 'com.example.app:id/image_view',
    })

  def testFind_byMultiple(self):
    node = self.app.GetUiNode(resource_id='image_view',
                              content_desc='Promotions')
    self.assertNodeHasAttribs(node, {
        'content-desc': 'Promotions',
        'resource-id': 'com.example.app:id/image_view',
    })
    self.assertEquals(node.bounds, geometry.Rectangle([16, 578], [128, 690]))

  def testFind_notFound(self):
    node = self.app.GetUiNode(resource_id='does_not_exist')
    self.assertIsNone(node)

  def testFind_noArgsGiven(self):
    # Same exception given by Python for a function call with not enough args.
    with self.assertRaises(TypeError):
      self.app.GetUiNode()

  def testGetChildren(self):
    node = self.app.GetUiNode(resource_id='mini_drawer')
    self.assertNodeHasAttribs(
        node[0], {'resource-id': 'com.example.app:id/avatar'})
    self.assertNodeHasAttribs(node[1], {'content-desc': 'Primary'})
    self.assertNodeHasAttribs(node[2], {'content-desc': 'Social'})
    self.assertNodeHasAttribs(node[3], {'content-desc': 'Promotions'})
    with self.assertRaises(IndexError):
      # pylint: disable=pointless-statement
      node[4]

  def testTap_center(self):
    node = self.app.GetUiNode(content_desc='Open navigation drawer')
    node.Tap()
    self.assertTappedOnceAt(56, 114)

  def testTap_topleft(self):
    node = self.app.GetUiNode(content_desc='Open navigation drawer')
    node.Tap(geometry.Point(0, 0))
    self.assertTappedOnceAt(0, 58)

  def testTap_withOffset(self):
    node = self.app.GetUiNode(content_desc='Open navigation drawer')
    node.Tap(geometry.Point(10, 20))
    self.assertTappedOnceAt(10, 78)

  def testTap_withOffsetInDp(self):
    node = self.app.GetUiNode(content_desc='Open navigation drawer')
    node.Tap(geometry.Point(10, 20), dp_units=True)
    self.assertTappedOnceAt(20, 98)

  def testTap_dpUnitsIgnored(self):
    node = self.app.GetUiNode(content_desc='Open navigation drawer')
    node.Tap(dp_units=True)
    self.assertTappedOnceAt(56, 114)  # Still taps at center.

  @mock.patch('time.sleep', mock.Mock())
  def testWaitForUiNode_found(self):
    self._setMockXmlScreenshots(
        [MOCK_XML_LOADING, MOCK_XML_LOADING, MOCK_XML_LOADED])
    node = self.app.WaitForUiNode(resource_id='actionbar_title')
    self.assertNodeHasAttribs(node, {'text': 'Primary'})

  @mock.patch('time.sleep', mock.Mock())
  def testWaitForUiNode_notFound(self):
    self._setMockXmlScreenshots(
        [MOCK_XML_LOADING, MOCK_XML_LOADING, MOCK_XML_LOADING])
    with self.assertRaises(device_errors.CommandTimeoutError):
      self.app.WaitForUiNode(resource_id='actionbar_title')
