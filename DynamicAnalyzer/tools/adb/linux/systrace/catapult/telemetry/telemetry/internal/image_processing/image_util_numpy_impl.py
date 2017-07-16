# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from __future__ import division

import warnings

from telemetry.internal.util import external_modules
from telemetry.util import color_histogram
from telemetry.util import rgba_color
import png

cv2 = external_modules.ImportOptionalModule('cv2')
np = external_modules.ImportRequiredModule('numpy')


def Channels(image):
  return image.shape[2]

def Width(image):
  return image.shape[1]

def Height(image):
  return image.shape[0]

def Pixels(image):
  return bytearray(np.uint8(image[:, :, ::-1]).flat)  # Convert from bgr to rgb.

def GetPixelColor(image, x, y):
  bgr = image[y][x]
  return rgba_color.RgbaColor(bgr[2], bgr[1], bgr[0])

def WritePngFile(image, path):
  if cv2 is not None:
    cv2.imwrite(path, image)
  else:
    with open(path, "wb") as f:
      metadata = {}
      metadata['size'] = (Width(image), Height(image))
      metadata['alpha'] = False
      metadata['bitdepth'] = 8
      img = image[:, :, ::-1]
      pixels = img.reshape(-1).tolist()
      png.Writer(**metadata).write_array(f, pixels)

def FromRGBPixels(width, height, pixels, bpp):
  img = np.array(pixels, order='F', dtype=np.uint8)
  img.resize((height, width, bpp))
  if bpp == 4:
    img = img[:, :, :3]  # Drop alpha.
  return img[:, :, ::-1]  # Convert from rgb to bgr.

def FromPngFile(path):
  if cv2 is not None:
    img = cv2.imread(path, cv2.CV_LOAD_IMAGE_COLOR)
    if img is None:
      raise ValueError('Image at path {0} could not be read'.format(path))
    return img
  else:
    with open(path, "rb") as f:
      return FromPng(f.read())

def FromPng(png_data):
  if cv2 is not None:
    file_bytes = np.asarray(bytearray(png_data), dtype=np.uint8)
    return cv2.imdecode(file_bytes, cv2.CV_LOAD_IMAGE_COLOR)
  else:
    warnings.warn(
        'Using pure python png decoder, which could be very slow. To speed up, '
        'consider installing numpy & cv2 (OpenCV).')
    width, height, pixels, meta = png.Reader(bytes=png_data).read_flat()
    return FromRGBPixels(width, height, pixels, 4 if meta['alpha'] else 3)

def _SimpleDiff(image1, image2):
  if cv2 is not None:
    return cv2.absdiff(image1, image2)
  else:
    amax = np.maximum(image1, image2)
    amin = np.minimum(image1, image2)
    return amax - amin

def AreEqual(image1, image2, tolerance, likely_equal):
  if image1.shape != image2.shape:
    return False
  self_image = image1
  other_image = image2
  if tolerance:
    if likely_equal:
      return np.amax(_SimpleDiff(image1, image2)) <= tolerance
    else:
      for row in xrange(Height(image1)):
        if np.amax(_SimpleDiff(image1[row], image2[row])) > tolerance:
          return False
      return True
  else:
    if likely_equal:
      return (self_image == other_image).all()
    else:
      for row in xrange(Height(image1)):
        if not (self_image[row] == other_image[row]).all():
          return False
      return True

def Diff(image1, image2):
  self_image = image1
  other_image = image2
  if image1.shape[2] != image2.shape[2]:
    raise ValueError('Cannot diff images of differing bit depth')
  if image1.shape[:2] != image2.shape[:2]:
    width = max(Width(image1), Width(image2))
    height = max(Height(image1), Height(image2))
    self_image = np.zeros((width, height, image1.shape[2]), np.uint8)
    other_image = np.zeros((width, height, image1.shape[2]), np.uint8)
    self_image[0:Height(image1), 0:Width(image1)] = image1
    other_image[0:Height(image2), 0:Width(image2)] = image2
  return _SimpleDiff(self_image, other_image)

def GetBoundingBox(image, color, tolerance):
  if cv2 is not None:
    color = np.array([color.b, color.g, color.r])
    img = cv2.inRange(image, np.subtract(color[0:3], tolerance),
                      np.add(color[0:3], tolerance))
    count = cv2.countNonZero(img)
    if count == 0:
      return None, 0
    contours, _ = cv2.findContours(img, cv2.RETR_LIST, cv2.CHAIN_APPROX_NONE)
    contour = np.concatenate(contours)
    return cv2.boundingRect(contour), count
  else:
    if tolerance:
      color = np.array([color.b, color.g, color.r])
      colorm = color - tolerance
      colorp = color + tolerance
      b = image[:, :, 0]
      g = image[:, :, 1]
      r = image[:, :, 2]
      w = np.where(((b >= colorm[0]) & (b <= colorp[0]) &
                    (g >= colorm[1]) & (g <= colorp[1]) &
                    (r >= colorm[2]) & (r <= colorp[2])))
    else:
      w = np.where((image[:, :, 0] == color.b) &
                   (image[:, :, 1] == color.g) &
                   (image[:, :, 2] == color.r))
    if len(w[0]) == 0:
      return None, 0
    return (w[1][0], w[0][0], w[1][-1] - w[1][0] + 1, w[0][-1] - w[0][0] + 1), \
        len(w[0])

def Crop(image, left, top, width, height):
  img_height, img_width = image.shape[:2]
  if (left < 0 or top < 0 or
      (left + width) > img_width or
      (top + height) > img_height):
    raise ValueError('Invalid dimensions')
  return image[top:top + height, left:left + width]

def GetColorHistogram(image, ignore_color, tolerance):
  if cv2 is not None:
    mask = None
    if ignore_color is not None:
      color = np.array([ignore_color.b, ignore_color.g, ignore_color.r])
      mask = ~cv2.inRange(image, np.subtract(color, tolerance),
                          np.add(color, tolerance))

    flatten = np.ndarray.flatten
    hist_b = flatten(cv2.calcHist([image], [0], mask, [256], [0, 256]))
    hist_g = flatten(cv2.calcHist([image], [1], mask, [256], [0, 256]))
    hist_r = flatten(cv2.calcHist([image], [2], mask, [256], [0, 256]))
  else:
    filtered = image.reshape(-1, 3)
    if ignore_color is not None:
      color = np.array([ignore_color.b, ignore_color.g, ignore_color.r])
      colorm = np.array(color) - tolerance
      colorp = np.array(color) + tolerance
      in_range = ((filtered[:, 0] < colorm[0]) | (filtered[:, 0] > colorp[0]) |
                  (filtered[:, 1] < colorm[1]) | (filtered[:, 1] > colorp[1]) |
                  (filtered[:, 2] < colorm[2]) | (filtered[:, 2] > colorp[2]))
      filtered = np.compress(in_range, filtered, axis=0)
    if len(filtered[:, 0]) == 0:
      return color_histogram.ColorHistogram(np.zeros((256)), np.zeros((256)),
                                      np.zeros((256)), ignore_color)
    hist_b = np.bincount(filtered[:, 0], minlength=256)
    hist_g = np.bincount(filtered[:, 1], minlength=256)
    hist_r = np.bincount(filtered[:, 2], minlength=256)

  return color_histogram.ColorHistogram(hist_r, hist_g, hist_b, ignore_color)
