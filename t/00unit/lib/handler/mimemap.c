/*
 * Copyright (c) 2014 DeNA Co., Ltd.
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
#include "../../test.h"
#include "../../../../lib/handler/mimemap.c"

static void test_default_attributes(void)
{
    vhttp_mime_attributes_t attr;

    vhttp_mimemap_get_default_attributes("text/plain", &attr);
    ok(attr.is_compressible);
    ok(attr.priority == vhttp_MIME_ATTRIBUTE_PRIORITY_NORMAL);

    vhttp_mimemap_get_default_attributes("text/plain; charset=utf-8", &attr);
    ok(attr.is_compressible);
    ok(attr.priority == vhttp_MIME_ATTRIBUTE_PRIORITY_NORMAL);

    vhttp_mimemap_get_default_attributes("application/xhtml+xml", &attr);
    ok(attr.is_compressible);
    ok(attr.priority == vhttp_MIME_ATTRIBUTE_PRIORITY_NORMAL);

    vhttp_mimemap_get_default_attributes("application/xhtml+xml; charset=utf-8", &attr);
    ok(attr.is_compressible);
    ok(attr.priority == vhttp_MIME_ATTRIBUTE_PRIORITY_NORMAL);

    vhttp_mimemap_get_default_attributes("text/css", &attr);
    ok(attr.is_compressible);
    ok(attr.priority == vhttp_MIME_ATTRIBUTE_PRIORITY_HIGHEST);

    vhttp_mimemap_get_default_attributes("text/css; charset=utf-8", &attr);
    ok(attr.is_compressible);
    ok(attr.priority == vhttp_MIME_ATTRIBUTE_PRIORITY_HIGHEST);

    vhttp_mimemap_get_default_attributes("application/octet-stream", &attr);
    ok(!attr.is_compressible);
    ok(attr.priority == vhttp_MIME_ATTRIBUTE_PRIORITY_NORMAL);
}

static int is_mimetype(vhttp_mimemap_type_t *type, const char *expected)
{
    return type->type == vhttp_MIMEMAP_TYPE_MIMETYPE && type->data.mimetype.len == strlen(expected) &&
           memcmp(type->data.mimetype.base, expected, type->data.mimetype.len) == 0;
}

static void test_basic()
{
    vhttp_mimemap_t *mimemap = vhttp_mimemap_create(), *mimemap2;

    subtest("default-attributes", test_default_attributes);

    /* default and set default */
    ok(is_mimetype(vhttp_mimemap_get_default_type(mimemap), "application/octet-stream"));
    {
        char buf[sizeof("text/plain")];
        strcpy(buf, "text/plain");
        vhttp_mimemap_set_default_type(mimemap, buf, NULL);
        memset(buf, 0, sizeof(buf));
    }
    ok(is_mimetype(vhttp_mimemap_get_default_type(mimemap), "text/plain"));

    /* set and overwrite */
    vhttp_mimemap_define_mimetype(mimemap, "foo", "example/foo", NULL);
    ok(is_mimetype(vhttp_mimemap_get_type_by_extension(mimemap, vhttp_iovec_init(vhttp_STRLIT("foo"))), "example/foo"));
    ok(is_mimetype(vhttp_mimemap_get_type_by_extension(mimemap, vhttp_iovec_init(vhttp_STRLIT("FOO"))), "example/foo"));
    ok(vhttp_mimemap_get_type_by_extension(mimemap, vhttp_iovec_init(vhttp_STRLIT("foo"))) ==
       vhttp_mimemap_get_type_by_mimetype(mimemap, vhttp_iovec_init(vhttp_STRLIT("example/foo")), 0));
    vhttp_mimemap_define_mimetype(mimemap, "foo", "example/overwritten", NULL);
    ok(is_mimetype(vhttp_mimemap_get_type_by_extension(mimemap, vhttp_iovec_init(vhttp_STRLIT("foo"))), "example/overwritten"));
    ok(vhttp_mimemap_get_type_by_extension(mimemap, vhttp_iovec_init(vhttp_STRLIT("foo"))) ==
       vhttp_mimemap_get_type_by_mimetype(mimemap, vhttp_iovec_init(vhttp_STRLIT("example/overwritten")), 0));
    ok(vhttp_mimemap_get_type_by_mimetype(mimemap, vhttp_iovec_init(vhttp_STRLIT("example/foo")), 0) == NULL);

    /* clone and release */
    mimemap2 = vhttp_mimemap_clone(mimemap);
    ok(is_mimetype(vhttp_mimemap_get_default_type(mimemap2), "text/plain"));
    ok(is_mimetype(vhttp_mimemap_get_type_by_extension(mimemap2, vhttp_iovec_init(vhttp_STRLIT("foo"))), "example/overwritten"));
    ok(vhttp_mimemap_get_type_by_extension(mimemap, vhttp_iovec_init(vhttp_STRLIT("foo"))) ==
       vhttp_mimemap_get_type_by_mimetype(mimemap, vhttp_iovec_init(vhttp_STRLIT("example/overwritten")), 0));
    vhttp_mem_release_shared(mimemap2);

    /* check original */
    ok(is_mimetype(vhttp_mimemap_get_default_type(mimemap), "text/plain"));
    ok(is_mimetype(vhttp_mimemap_get_type_by_extension(mimemap, vhttp_iovec_init(vhttp_STRLIT("foo"))), "example/overwritten"));

    /* remove */
    vhttp_mimemap_remove_type(mimemap, "foo");
    ok(is_mimetype(vhttp_mimemap_get_type_by_extension(mimemap, vhttp_iovec_init(vhttp_STRLIT("foo"))), "text/plain"));
    ok(vhttp_mimemap_get_type_by_mimetype(mimemap, vhttp_iovec_init(vhttp_STRLIT("example/overwritten")), 0) == NULL);
    vhttp_mimemap_remove_type(mimemap, "foo");
    ok(is_mimetype(vhttp_mimemap_get_type_by_extension(mimemap, vhttp_iovec_init(vhttp_STRLIT("foo"))), "text/plain"));

    vhttp_mem_release_shared(mimemap);
}

static void test_dynamic()
{
    vhttp_mimemap_t *mimemap = vhttp_mimemap_create();
    const char *exts[] = {".php", NULL};
    vhttp_globalconf_t global = {NULL};
    vhttp_mimemap_define_dynamic(mimemap, exts, &global);
    vhttp_mem_release_shared(mimemap);
}

void test_lib__handler__mimemap_c()
{
    subtest("basic", test_basic);
    subtest("dynamic", test_dynamic);
}
