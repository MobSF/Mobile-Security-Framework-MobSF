# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""
The Value hierarchy provides a way of representing the values measurements
produce such that they can be merged across runs, grouped by page, and output
to different targets.

The core Value concept provides the basic functionality:
- association with a page, may be none
- naming and units
- importance tracking [whether a value will show up on a waterfall or output
  file by default]
- other metadata, such as a description of what was measured
- default conversion to scalar and string
- merging properties

A page may actually run a few times during a single telemetry session.
Downstream consumers of test results typically want to group these runs
together, then compute summary statistics across runs. Value provides the
Merge* family of methods for this kind of aggregation.
"""
import os

from telemetry.core import discover
from telemetry.core import util

# When converting a Value to its buildbot equivalent, the context in which the
# value is being interpreted actually affects the conversion. This is insane,
# but there you have it. There are three contexts in which Values are converted
# for use by buildbot, represented by these output-intent values.
PER_PAGE_RESULT_OUTPUT_CONTEXT = 'per-page-result-output-context'
COMPUTED_PER_PAGE_SUMMARY_OUTPUT_CONTEXT = 'merged-pages-result-output-context'
SUMMARY_RESULT_OUTPUT_CONTEXT = 'summary-result-output-context'

class Value(object):
  """An abstract value produced by a telemetry page test.
  """
  def __init__(self, page, name, units, important, description,
               tir_label, grouping_keys):
    """A generic Value object.

    Args:
      page: A Page object, may be given as None to indicate that the value
          represents results for multiple pages.
      name: A value name string, may contain a dot. Values from the same test
          with the same prefix before the dot may be considered to belong to
          the same chart.
      units: A units string.
      important: Whether the value is "important". Causes the value to appear
          by default in downstream UIs.
      description: A string explaining in human-understandable terms what this
          value represents.
      tir_label: The string label of the TimelineInteractionRecord with
          which this value is associated.
      grouping_keys: A dict that maps grouping key names to grouping keys.
    """
    # TODO(eakuefner): Check story here after migration (crbug.com/442036)
    if not isinstance(name, basestring):
      raise ValueError('name field of Value must be string.')
    if not isinstance(units, basestring):
      raise ValueError('units field of Value must be string.')
    if not isinstance(important, bool):
      raise ValueError('important field of Value must be bool.')
    if not ((description is None) or isinstance(description, basestring)):
      raise ValueError('description field of Value must absent or string.')
    if not ((tir_label is None) or
            isinstance(tir_label, basestring)):
      raise ValueError('tir_label field of Value must absent or '
                       'string.')
    if not ((grouping_keys is None) or isinstance(grouping_keys, dict)):
      raise ValueError('grouping_keys field of Value must be absent or dict')

    if grouping_keys is None:
      grouping_keys = {}

    self.page = page
    self.name = name
    self.units = units
    self.important = important
    self.description = description
    self.tir_label = tir_label
    self.grouping_keys = grouping_keys

  def __eq__(self, other):
    return hash(self) == hash(other)

  def __hash__(self):
    return hash(str(self))

  def IsMergableWith(self, that):
    return (self.units == that.units and
            type(self) == type(that) and
            self.important == that.important)

  @classmethod
  def MergeLikeValuesFromSamePage(cls, values):
    """Combines the provided list of values into a single compound value.

    When a page runs multiple times, it may produce multiple values. This
    function is given the same-named values across the multiple runs, and has
    the responsibility of producing a single result.

    It must return a single Value. If merging does not make sense, the
    implementation must pick a representative value from one of the runs.

    For instance, it may be given
        [ScalarValue(page, 'a', 1), ScalarValue(page, 'a', 2)]
    and it might produce
        ListOfScalarValues(page, 'a', [1, 2])
    """
    raise NotImplementedError()

  @classmethod
  def MergeLikeValuesFromDifferentPages(cls, values):
    """Combines the provided values into a single compound value.

    When a full pageset runs, a single value_name will usually end up getting
    collected for multiple pages. For instance, we may end up with
       [ScalarValue(page1, 'a',  1),
        ScalarValue(page2, 'a',  2)]

    This function takes in the values of the same name, but across multiple
    pages, and produces a single summary result value. In this instance, it
    could produce a ScalarValue(None, 'a', 1.5) to indicate averaging, or even
    ListOfScalarValues(None, 'a', [1, 2]) if concatenated output was desired.

    Some results are so specific to a page that they make no sense when
    aggregated across pages. If merging values of this type across pages is
    non-sensical, this method may return None.
    """
    raise NotImplementedError()

  def _IsImportantGivenOutputIntent(self, output_context):
    if output_context == PER_PAGE_RESULT_OUTPUT_CONTEXT:
      return False
    elif output_context == COMPUTED_PER_PAGE_SUMMARY_OUTPUT_CONTEXT:
      return self.important
    elif output_context == SUMMARY_RESULT_OUTPUT_CONTEXT:
      return self.important

  def GetBuildbotDataType(self, output_context):
    """Returns the buildbot's equivalent data_type.

    This should be one of the values accepted by perf_tests_results_helper.py.
    """
    raise NotImplementedError()

  def GetBuildbotValue(self):
    """Returns the buildbot's equivalent value."""
    raise NotImplementedError()

  def GetChartAndTraceNameForPerPageResult(self):
    chart_name, _ = _ConvertValueNameToChartAndTraceName(self.name)
    trace_name = self.page.display_name
    return chart_name, trace_name

  @property
  def name_suffix(self):
    """Returns the string after a . in the name, or the full name otherwise."""
    if '.' in self.name:
      return self.name.split('.', 1)[1]
    else:
      return self.name

  def GetChartAndTraceNameForComputedSummaryResult(
      self, trace_tag):
    chart_name, trace_name = (
        _ConvertValueNameToChartAndTraceName(self.name))
    if trace_tag:
      return chart_name, trace_name + trace_tag
    else:
      return chart_name, trace_name

  def GetRepresentativeNumber(self):
    """Gets a single scalar value that best-represents this value.

    Returns None if not possible.
    """
    raise NotImplementedError()

  def GetRepresentativeString(self):
    """Gets a string value that best-represents this value.

    Returns None if not possible.
    """
    raise NotImplementedError()

  @staticmethod
  def GetJSONTypeName():
    """Gets the typename for serialization to JSON using AsDict."""
    raise NotImplementedError()

  def AsDict(self):
    """Pre-serializes a value to a dict for output as JSON."""
    return self._AsDictImpl()

  def _AsDictImpl(self):
    d = {
      'name': self.name,
      'type': self.GetJSONTypeName(),
      'units': self.units,
      'important': self.important
    }

    if self.description:
      d['description'] = self.description

    if self.tir_label:
      d['tir_label'] = self.tir_label

    if self.page:
      d['page_id'] = self.page.id

    if self.grouping_keys:
      d['grouping_keys'] = self.grouping_keys

    return d

  def AsDictWithoutBaseClassEntries(self):
    full_dict = self.AsDict()
    base_dict_keys = set(self._AsDictImpl().keys())

    # Extracts only entries added by the subclass.
    return dict([(k, v) for (k, v) in full_dict.iteritems()
                  if k not in base_dict_keys])

  @staticmethod
  def FromDict(value_dict, page_dict):
    """Produces a value from a value dict and a page dict.

    Value dicts are produced by serialization to JSON, and must be accompanied
    by a dict mapping page IDs to pages, also produced by serialization, in
    order to be completely deserialized. If deserializing multiple values, use
    ListOfValuesFromListOfDicts instead.

    value_dict: a dictionary produced by AsDict() on a value subclass.
    page_dict: a dictionary mapping IDs to page objects.
    """
    return Value.ListOfValuesFromListOfDicts([value_dict], page_dict)[0]

  @staticmethod
  def ListOfValuesFromListOfDicts(value_dicts, page_dict):
    """Takes a list of value dicts to values.

    Given a list of value dicts produced by AsDict, this method
    deserializes the dicts given a dict mapping page IDs to pages.
    This method performs memoization for deserializing a list of values
    efficiently, where FromDict is meant to handle one-offs.

    values: a list of value dicts produced by AsDict() on a value subclass.
    page_dict: a dictionary mapping IDs to page objects.
    """
    value_dir = os.path.dirname(__file__)
    value_classes = discover.DiscoverClasses(
        value_dir, util.GetTelemetryDir(),
        Value, index_by_class_name=True)

    value_json_types = dict((value_classes[x].GetJSONTypeName(), x) for x in
        value_classes)

    values = []
    for value_dict in value_dicts:
      value_class = value_classes[value_json_types[value_dict['type']]]
      assert 'FromDict' in value_class.__dict__, \
             'Subclass doesn\'t override FromDict'
      values.append(value_class.FromDict(value_dict, page_dict))

    return values

  @staticmethod
  def GetConstructorKwArgs(value_dict, page_dict):
    """Produces constructor arguments from a value dict and a page dict.

    Takes a dict parsed from JSON and an index of pages and recovers the
    keyword arguments to be passed to the constructor for deserializing the
    dict.

    value_dict: a dictionary produced by AsDict() on a value subclass.
    page_dict: a dictionary mapping IDs to page objects.
    """
    d = {
      'name': value_dict['name'],
      'units': value_dict['units']
    }

    description = value_dict.get('description', None)
    if description:
      d['description'] = description
    else:
      d['description'] = None

    page_id = value_dict.get('page_id', None)
    if page_id is not None:
      d['page'] = page_dict[int(page_id)]
    else:
      d['page'] = None

    d['important'] = False

    tir_label = value_dict.get('tir_label', None)
    if tir_label:
      d['tir_label'] = tir_label
    else:
      d['tir_label'] = None

    grouping_keys = value_dict.get('grouping_keys', None)
    if grouping_keys:
      d['grouping_keys'] = grouping_keys
    else:
      d['grouping_keys'] = None

    return d


def MergedTirLabel(values):
  """Returns the tir_label that should be applied to a merge of values.

  As of TBMv2, we encounter situations where we need to merge values with
  different tir_labels because Telemetry's tir_label field is being used to
  store story keys for system health stories. As such, when merging, we want to
  take the common tir_label if all values share the same label (legacy
  behavior), or have no tir_label if not.

  Args:
    values: a list of Value instances

  Returns:
    The tir_label that would be set on the merge of |values|.
  """
  assert len(values) > 0
  v0 = values[0]

  first_tir_label = v0.tir_label
  if all(v.tir_label == first_tir_label for v in values):
    return first_tir_label
  else:
    return None


def ValueNameFromTraceAndChartName(trace_name, chart_name=None):
  """Mangles a trace name plus optional chart name into a standard string.

  A value might just be a bareword name, e.g. numPixels. In that case, its
  chart may be None.

  But, a value might also be intended for display with other values, in which
  case the chart name indicates that grouping. So, you might have
  screen.numPixels, screen.resolution, where chartName='screen'.
  """
  assert trace_name != 'url', 'The name url cannot be used'
  if chart_name:
    return '%s.%s' % (chart_name, trace_name)
  else:
    assert '.' not in trace_name, ('Trace names cannot contain "." with an '
        'empty chart_name since this is used to delimit chart_name.trace_name.')
    return trace_name


def _ConvertValueNameToChartAndTraceName(value_name):
  """Converts a value_name into the equivalent chart-trace name pair.

  Buildbot represents values by the measurement name and an optional trace name,
  whereas telemetry represents values with a chart_name.trace_name convention,
  where chart_name is optional. This convention is also used by chart_json.

  This converts from the telemetry convention to the buildbot convention,
  returning a 2-tuple (measurement_name, trace_name).
  """
  if '.' in value_name:
    return value_name.split('.', 1)
  else:
    return value_name, value_name
