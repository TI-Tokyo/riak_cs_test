#!/usr/bin/env python
# -*- coding: utf-8 -*-
## ---------------------------------------------------------------------
##
## Copyright (c) 2007-2013 Basho Technologies, Inc.  All Rights Reserved.
##               2021 TI Tokyo    All Rights Reserved.
##
## This file is provided to you under the Apache License,
## Version 2.0 (the "License"); you may not use this file
## except in compliance with the License.  You may obtain
## a copy of the License at
##
##   http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing,
## software distributed under the License is distributed on an
## "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
## KIND, either express or implied.  See the License for the
## specific language governing permissions and limitations
## under the License.
##
## ---------------------------------------------------------------------

from boto_test_base import *
import uuid

class VersioningTests(S3ApiVerificationTestBase):

    def test_set_bucket_versioning(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        self.assertEqual(self.getBucketVersioning(bucket = bucket), 'Suspended')

        self.putBucketVersioning(bucket = bucket,
                                 status = 'Enabled')
        res = self.getBucketVersioning(bucket = bucket)
        self.assertEqual(self.getBucketVersioning(bucket = bucket), 'Enabled')

        self.putBucketVersioning(bucket = bucket,
                                 status = 'Suspended',
                                 canUpdateVersions = True,
                                 replSiblings = False)
        res = self.getBucketVersioning(bucket = bucket)
        self.assertEqual(self.getBucketVersioning(bucket = bucket), 'Suspended')
        # boto3 does not extract Riak CS specific fields, but they could be seen in the response body
        self.deleteBucket(bucket = bucket)

    def test_basic_crud(self):
        bucket = str(uuid.uuid4())
        key = "one"
        val1 = bytes('ფაფა', encoding='utf-8')
        val2 = bytes('ქექე', encoding='utf-8')
        self.createBucket(bucket = bucket)
        self.putBucketVersioning(bucket = bucket,
                                 status = 'Enabled')
        #boto3.set_stream_logger('')
        v1 = self.putObject(bucket = bucket, key = key, value = val1)
        v2 = self.putObject(bucket = bucket, key = key, value = val2)

        vv = [i['VersionId'] for i in self.listObjectVersions(bucket = bucket)]
        self.assertEqual(len(vv), 2)
        self.assertIn(v1, vv)
        self.assertIn(v2, vv)

        self.assertEqual(self.getObject(bucket = bucket, key = key, vsn = v1), val1)
        self.assertEqual(self.getObject(bucket = bucket, key = key, vsn = v2), val2)

        self.deleteObject(bucket = bucket, key = key, vsn = v1)
        vv = self.listObjectVersions(bucket = bucket)
        self.assertEqual(len(vv), 1)
        self.assertEqual(key, vv[0]["Key"])
        self.assertEqual(v2, vv[0]["VersionId"])
        self.assertEqual(self.getObject(bucket = bucket, key = key, vsn = v2), val2)
        self.deleteBucket(bucket = bucket)

    def test_crud_with_suspend(self):
        bucket = str(uuid.uuid4())
        key0, val0, vsn0 = "one", b"ONE", 'null'
        key1, val1 = "zero", b"Zero"
        self.createBucket(bucket = bucket)

        vsn0 = self.putObject(bucket = bucket, key = key0, value = val0)
        self.assertEqual(vsn0, 'null')

        self.putBucketVersioning(bucket = bucket,
                                 status = 'Enabled')
        self.assertEqual(self.getObject(bucket = bucket, key = key0), val0)
        self.assertEqual(self.getObject(bucket = bucket, key = key0, vsn = vsn0), val0)

        #boto3.set_stream_logger('')
        val4 = b"a new value, at autogenerated vsn"
        vsn4 = self.putObject(bucket = bucket, key = key0, value = val4)
        self.assertEqual(self.getObject(bucket = bucket, key = key0, vsn = vsn4), val4)

        # an earlier versioned value continues to exist and be accessible
        self.assertEqual(self.getObject(bucket = bucket, key = key0, vsn = vsn0), val0)

        # now there are two versions: "null" and an autogenerated one
        vv = [i['VersionId'] for i in self.listObjectVersions(bucket = bucket)]
        self.assertEqual(len(vv), 2)
        self.assertIn(vsn0, vv)
        self.assertIn(vsn4, vv)

        self.putBucketVersioning(bucket = bucket,
                                 status = 'Suspended')

        # versioned value continues to exist and be accessible, even if versioning is suspended
        self.assertEqual(self.getObject(bucket = bucket, key = key0, vsn = vsn4), val4)
        # null value, likewise
        self.assertEqual(self.getObject(bucket = bucket, key = key0), val0)

        vv = [i['VersionId'] for i in self.listObjectVersions(bucket = bucket)]
        self.assertIn(vsn0, vv)
        self.assertIn(vsn4, vv)

        val4 = b"overwriting at vsn null"
        vsn4 = self.putObject(bucket = bucket, key = key0, value = val4)
        self.assertEqual(vsn4, "null")
        self.assertEqual(self.getObject(bucket = bucket, key = key0), val4)

        self.deleteObject(bucket = bucket, key = key0)
        vv = self.listObjectVersions(bucket = bucket)
        self.assertEqual(len(vv), 1)
        self.assertNotIn("null", vv)

        self.deleteBucket(bucket = bucket)

    def test_multipart_crud(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        self.putBucketVersioning(bucket = bucket,
                                 status = 'Enabled')
        parts = [b'this is part one', b'part two is just a rewording',
                 b'surprise that part three is pretty much the same',
                 b'and the last part is number four']
        self.multipart_md5_helper(bucket, parts)
        self.deleteBucket(bucket = bucket)

    def test_multiuser_crud(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        self.putBucketVersioning(bucket = bucket,
                                 status = 'Enabled')

