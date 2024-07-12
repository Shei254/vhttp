/*
 * Copyright (c) 2014-2023 DeNA Co., Ltd., Kazuho Oku, Fastly
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef vhttp__version_h
#define vhttp__version_h

#ifdef vhttp_HAS_GITREV_H
#include "vhttp-gitrev.h"
#endif

#define vhttp_VERSION_BASE "2.3.0-DEV"
#define vhttp_VERSION_MAJOR 2
#define vhttp_VERSION_MINOR 3
#define vhttp_VERSION_PATCH 0

#ifdef vhttp_GITREV
#define vhttp_VERSION vhttp_VERSION_BASE "@" vhttp_TO_STR(vhttp_GITREV)
#else
#define vhttp_VERSION vhttp_VERSION_BASE
#endif

/* `vhttp_LIBRARY_VERSION` is a hard-coded string with three digits, that's the format we parse in CMakeLists.txt */
#define vhttp_LIBRARY_VERSION "0.16.0"
#define vhttp_LIBRARY_VERSION_MAJOR 0
#define vhttp_LIBRARY_VERSION_MINOR 16
#define vhttp_LIBRARY_VERSION_PATCH 0

#endif
