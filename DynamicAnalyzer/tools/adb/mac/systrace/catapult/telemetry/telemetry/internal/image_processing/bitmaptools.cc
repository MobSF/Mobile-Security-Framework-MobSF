// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(WIN32)
#include <fcntl.h>
#include <io.h>
#endif

enum Commands {
  CROP_PIXELS = 0,
  HISTOGRAM = 1,
  BOUNDING_BOX = 2
};

bool ReadInt(int* out) {
  return fread(out, sizeof(*out), 1, stdin) == 1;
}

void WriteResponse(void* data, int size) {
  fwrite(&size, sizeof(size), 1, stdout);
  fwrite(data, size, 1, stdout);
  fflush(stdout);
}

struct Box {
  Box() : left(), top(), right(), bottom() {}

  // Expected input is:
  // left, top, width, height
  bool Read() {
    int width;
    int height;
    if (!(ReadInt(&left) && ReadInt(&top) &&
          ReadInt(&width) && ReadInt(&height))) {
      fprintf(stderr, "Could not parse Box.\n");
      return false;
    }
    if (left < 0 || top < 0 || width < 0 || height < 0) {
      fprintf(stderr, "Box dimensions must be non-negative.\n");
      return false;
    }
    right = left + width;
    bottom = top + height;
    return true;
  }

  void Union(int x, int y) {
    if (left > x) left = x;
    if (right <= x) right = x + 1;
    if (top > y) top = y;
    if (bottom <= y) bottom = y + 1;
  }

  int width() const { return right - left; }
  int height() const { return bottom - top; }

  int left;
  int top;
  int right;
  int bottom;
};


// Represents a bitmap buffer with a crop box.
struct Bitmap {
  Bitmap() : pixels(NULL) {}

  ~Bitmap() {
    if (pixels)
      delete[] pixels;
  }

  // Expected input is:
  // bpp, width, height, box, pixels
  bool Read() {
    int bpp;
    int width;
    int height;
    if (!(ReadInt(&bpp) && ReadInt(&width) && ReadInt(&height))) {
      fprintf(stderr, "Could not parse Bitmap initializer.\n");
      return false;
    }
    if (bpp <= 0 || width <= 0 || height <= 0) {
      fprintf(stderr, "Dimensions must be positive.\n");
      return false;
    }

    int size = width * height * bpp;

    row_stride = width * bpp;
    pixel_stride = bpp;
    total_size = size;
    row_size = row_stride;

    if (!box.Read()) {
      fprintf(stderr, "Expected crop box argument not found.\n");
      return false;
    }

    if (box.bottom * row_stride > total_size ||
        box.right * pixel_stride > row_size) {
      fprintf(stderr, "Crop box overflows the bitmap.\n");
      return false;
    }

    pixels = new unsigned char[size];
    if (fread(pixels, sizeof(pixels[0]), size, stdin) <
        static_cast<size_t>(size)) {
      fprintf(stderr, "Not enough pixels found,\n");
      return false;
    }

    total_size = (box.bottom - box.top) * row_stride;
    row_size = (box.right - box.left) * pixel_stride;
    data = pixels + box.top * row_stride + box.left * pixel_stride;
    return true;
  }

  void WriteCroppedPixels() const {
    int out_size = row_size * box.height();
    unsigned char* out = new unsigned char[out_size];
    unsigned char* dst = out;
    for (const unsigned char* row = data;
        row < data + total_size;
        row += row_stride, dst += row_size) {
      // No change in pixel_stride, so we can copy whole rows.
      memcpy(dst, row, row_size);
    }

    WriteResponse(out, out_size);
    delete[] out;
  }

  unsigned char* pixels;
  Box box;
  // Points at the top-left pixel in |pixels|.
  const unsigned char* data;
  // These counts are in bytes.
  int row_stride;
  int pixel_stride;
  int total_size;
  int row_size;
};


static inline
bool PixelsEqual(const unsigned char* pixel1, const unsigned char* pixel2,
                 int tolerance) {
  // Note: this works for both RGB and RGBA. Alpha channel is ignored.
  return (abs(pixel1[0] - pixel2[0]) <= tolerance) &&
         (abs(pixel1[1] - pixel2[1]) <= tolerance) &&
         (abs(pixel1[2] - pixel2[2]) <= tolerance);
}


static inline
bool PixelsEqual(const unsigned char* pixel, int color, int tolerance) {
  unsigned char pixel2[3] = { color >> 16, color >> 8, color };
  return PixelsEqual(pixel, pixel2, tolerance);
}


static
bool Histogram(const Bitmap& bmp) {
  int ignore_color;
  int tolerance;
  if (!(ReadInt(&ignore_color) && ReadInt(&tolerance))) {
    fprintf(stderr, "Could not parse HISTOGRAM command.\n");
    return false;
  }

  const int kLength = 3 * 256;
  int counts[kLength] = {};

  for (const unsigned char* row = bmp.data; row < bmp.data + bmp.total_size;
       row += bmp.row_stride) {
    for (const unsigned char* pixel = row; pixel < row + bmp.row_size;
       pixel += bmp.pixel_stride) {
      if (ignore_color >= 0 && PixelsEqual(pixel, ignore_color, tolerance))
        continue;
      ++(counts[256 * 0 + pixel[0]]);
      ++(counts[256 * 1 + pixel[1]]);
      ++(counts[256 * 2 + pixel[2]]);
    }
  }

  WriteResponse(counts, sizeof(counts));
  return true;
}


static
bool BoundingBox(const Bitmap& bmp) {
  int color;
  int tolerance;
  if (!(ReadInt(&color) && ReadInt(&tolerance))) {
    fprintf(stderr, "Could not parse BOUNDING_BOX command.\n");
    return false;
  }

  Box box;
  box.left = bmp.total_size;
  box.top = bmp.total_size;
  box.right = 0;
  box.bottom = 0;

  int count = 0;
  int y = 0;
  for (const unsigned char* row = bmp.data; row < bmp.data + bmp.total_size;
       row += bmp.row_stride, ++y) {
    int x = 0;
    for (const unsigned char* pixel = row; pixel < row + bmp.row_size;
         pixel += bmp.pixel_stride, ++x) {
      if (!PixelsEqual(pixel, color, tolerance))
        continue;
      box.Union(x, y);
      ++count;
    }
  }

  int response[] = { box.left, box.top, box.width(), box.height(), count };
  WriteResponse(response, sizeof(response));
  return true;
}


int main() {
  Bitmap bmp;
  int command;

#if defined(WIN32)
  _setmode(_fileno(stdin), _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);
#else
  stdin = freopen(NULL, "rb", stdin);
  stdout = freopen(NULL, "wb", stdout);
#endif

  if (!bmp.Read()) return -1;
  if (!ReadInt(&command)) {
    fprintf(stderr, "Expected command.\n");
    return -1;
  }
  switch (command) {
    case CROP_PIXELS:
      bmp.WriteCroppedPixels();
      break;
    case BOUNDING_BOX:
      if (!BoundingBox(bmp)) return -1;
      break;
    case HISTOGRAM:
      if (!Histogram(bmp)) return -1;
      break;
    default:
      fprintf(stderr, "Unrecognized command\n");
      return -1;
  }
  return 0;
}
