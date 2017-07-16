# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from __future__ import division

from telemetry.internal.image_processing import _bitmap


def Channels(bitmap):
  return bitmap.bpp

def Width(bitmap):
  return bitmap.width

def Height(bitmap):
  return bitmap.height

def Pixels(bitmap):
  return bitmap.pixels

def GetPixelColor(bitmap, x, y):
  return bitmap.GetPixelColor(x, y)

def WritePngFile(bitmap, path):
  bitmap.WritePngFile(path)

def FromRGBPixels(width, height, pixels, bpp):
  return _bitmap.Bitmap(bpp, width, height, pixels)

def FromPng(png_data):
  return _bitmap.Bitmap.FromPng(png_data)

def FromPngFile(path):
  return _bitmap.Bitmap.FromPngFile(path)

def AreEqual(bitmap1, bitmap2, tolerance, _):
  return bitmap1.IsEqual(bitmap2, tolerance)

def Diff(bitmap1, bitmap2):
  return bitmap1.Diff(bitmap2)

def GetBoundingBox(bitmap, color, tolerance):
  return bitmap.GetBoundingBox(color, tolerance)

def Crop(bitmap, left, top, width, height):
  return bitmap.Crop(left, top, width, height)

def GetColorHistogram(bitmap, ignore_color, tolerance):
  return bitmap.ColorHistogram(ignore_color, tolerance)
