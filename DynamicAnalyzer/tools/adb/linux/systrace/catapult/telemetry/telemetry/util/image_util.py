# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Provides implementations of basic image processing functions.

Implements basic image processing functions, such as reading/writing images,
cropping, finding the bounding box of a color and diffing images.

When numpy is present, image_util_numpy_impl is used for the implementation of
this interface. The old bitmap implementation (image_util_bitmap_impl) is used
as a fallback when numpy is not present."""

import base64

from telemetry.internal.util import external_modules

np = external_modules.ImportOptionalModule('numpy')

if np is None:
  from telemetry.internal.image_processing import image_util_bitmap_impl
  impl = image_util_bitmap_impl
else:
  from telemetry.internal.image_processing import image_util_numpy_impl
  impl = image_util_numpy_impl


def Channels(image):
  """Number of color channels in the image."""
  return impl.Channels(image)

def Width(image):
  """Width of the image."""
  return impl.Width(image)

def Height(image):
  """Height of the image."""
  return impl.Height(image)

def Pixels(image):
  """Flat RGB pixel array of the image."""
  return impl.Pixels(image)

def GetPixelColor(image, x, y):
  """Returns a RgbaColor for the pixel at (x, y)."""
  return impl.GetPixelColor(image, x, y)

def WritePngFile(image, path):
  """Write an image to a PNG file.

  Args:
    image: an image object.
    path: The path to the PNG file. Must end in 'png' or an
          AssertionError will be raised."""
  assert path.endswith('png')
  return impl.WritePngFile(image, path)

def FromRGBPixels(width, height, pixels, bpp=3):
  """Create an image from an array of rgb pixels.

  Ignores alpha channel if present.

  Args:
    width, height: int, the width and height of the image.
    pixels: The flat array of pixels in the form of [r,g,b[,a],r,g,b[,a],...]
    bpp: 3 for RGB, 4 for RGBA."""
  return impl.FromRGBPixels(width, height, pixels, bpp)

def FromPng(png_data):
  """Create an image from raw PNG data."""
  return impl.FromPng(png_data)

def FromPngFile(path):
  """Create an image from a PNG file.

  Args:
    path: The path to the PNG file."""
  return impl.FromPngFile(path)

def FromBase64Png(base64_png):
  """Create an image from raw PNG data encoded in base64."""
  return FromPng(base64.b64decode(base64_png))

def AreEqual(image1, image2, tolerance=0, likely_equal=True):
  """Determines whether two images are identical within a given tolerance.
  Setting likely_equal to False enables short-circuit equality testing, which
  is about 2-3x slower for equal images, but can be image height times faster
  if the images are not equal."""
  return impl.AreEqual(image1, image2, tolerance, likely_equal)

def Diff(image1, image2):
  """Returns a new image that represents the difference between this image
  and another image."""
  return impl.Diff(image1, image2)

def GetBoundingBox(image, color, tolerance=0):
  """Finds the minimum box surrounding all occurrences of bgr |color|.

  Ignores the alpha channel.

  Args:
    color: RbgaColor, bounding box color.
    tolerance: int, per-channel tolerance for the bounding box color.

  Returns:
    (top, left, width, height), match_count"""
  return impl.GetBoundingBox(image, color, tolerance)

def Crop(image, left, top, width, height):
  """Crops the current image down to the specified box."""
  return impl.Crop(image, left, top, width, height)

def GetColorHistogram(image, ignore_color=None, tolerance=0):
  """Computes a histogram of the pixel colors in this image.
  Args:
    ignore_color: An RgbaColor to exclude from the bucket counts.
    tolerance: A tolerance for the ignore_color.

  Returns:
    A ColorHistogram namedtuple with 256 integers in each field: r, g, and b."""
  return impl.GetColorHistogram(image, ignore_color, tolerance)
