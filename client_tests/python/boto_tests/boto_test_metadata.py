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
import json, uuid

class ObjectMetadataTest(S3ApiVerificationTestBase):
    "Test object metadata, e.g. Content-Encoding, x-amz-meta-*, for PUT/GET"

    metadata = {
        "Content-Disposition": 'attachment; filename="metaname.txt"',
        "Content-Encoding": 'identity',
        "Cache-Control": "max-age=3600",
        "Expires": "Tue, 19 Jan 2038 03:14:07 GMT",
        "mtime": "1364742057",
        "UID": "0",
        "with-hypen": "1",
        "space-in-value": "abc xyz"
    }
    updated_metadata = {
        "Content-Disposition": 'attachment; filename="newname.txt"',
        "Cache-Control": "private",
        "Expires": "Tue, 19 Jan 2038 03:14:07 GMT",
        "mtime": "2222222222",
        "uid": "0",
        "space-in-value": "ABC XYZ",
        "new-entry": "NEW"
    }

    def test_normal_object_metadata(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        self.putObject(bucket = bucket,
                       value = "test_normal_object_metadata",
                       metadata = self.metadata)
        self.assert_metadata(bucket, self.default_key)
        self.change_metadata(bucket, self.default_key)
        self.assert_updated_metadata(bucket, self.default_key)
        self.deleteBucket(bucket = bucket)

    def test_mp_object_metadata(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        key = str(uuid.uuid4())
        upload = self.upload_multipart(bucket, key, [b"part1"],
                                       metadata = self.metadata)
        self.assert_metadata(bucket, key)
        self.change_metadata(bucket, key)
        self.assert_updated_metadata(bucket, key)
        self.deleteBucket(bucket = bucket)

    def assert_metadata(self, bucket, key):
        res = self.client.get_object(Bucket = bucket,
                                     Key = key)

        hh = res['ResponseMetadata']['HTTPHeaders']
        md = res['Metadata']
        self.assertEqual(hh['x-amz-meta-content-disposition'], self.metadata['Content-Disposition']),
        self.assertEqual(hh['x-amz-meta-content-encoding'], self.metadata['Content-Encoding'])
        self.assertEqual(hh['x-amz-meta-cache-control'], self.metadata['Cache-Control'])
        self.assertEqual(hh['x-amz-meta-expires'], self.metadata['Expires'])
        self.assertEqual(hh['x-amz-meta-mtime'], self.metadata["mtime"])
        self.assertEqual(hh['x-amz-meta-uid'], self.metadata["UID"])
        self.assertEqual(hh['x-amz-meta-with-hypen'], self.metadata["with-hypen"])
        self.assertEqual(hh['x-amz-meta-space-in-value'], self.metadata["space-in-value"])
        # x-amz-meta-* headers should be normalized to lowercase
        self.assertEqual(md.get("Mtime"), None)
        self.assertEqual(md.get("MTIME"), None)
        self.assertEqual(md.get("Uid"), None)
        self.assertEqual(md.get("UID"), None)
        self.assertEqual(md.get("With-Hypen"), None)
        self.assertEqual(md.get("Space-In-Value"), None)

    def change_metadata(self, bucket, key):
        self.client.copy_object(Bucket = bucket,
                                Key = key,
                                CopySource = "%s/%s" % (bucket, key),
                                MetadataDirective = 'REPLACE',
                                Metadata = self.updated_metadata)

    def assert_updated_metadata(self, bucket, key):
        res = self.client.get_object(Bucket = bucket,
                                     Key = key)

        hh = res['ResponseMetadata']['HTTPHeaders']
        md = res['Metadata']
        expected_md = self.updated_metadata
        self.assertEqual(hh['x-amz-meta-content-disposition'], expected_md['Content-Disposition']),
        self.assertEqual(hh['x-amz-meta-cache-control'], expected_md['Cache-Control'])
        self.assertEqual(hh['x-amz-meta-expires'], expected_md['Expires'])
        self.assertEqual(hh['x-amz-meta-mtime'], expected_md["mtime"])
        self.assertEqual(hh['x-amz-meta-uid'], expected_md["uid"])
        self.assertEqual(hh['x-amz-meta-space-in-value'], expected_md["space-in-value"])
        # x-amz-meta-* headers should be normalized to lowercase
        self.assertEqual(md.get("Mtime"), None)
        self.assertEqual(md.get("MTIME"), None)
        self.assertEqual(md.get("Uid"), None)
        self.assertEqual(md.get("UID"), None)
        self.assertEqual(md.get("With-Hypen"), None)
        self.assertEqual(md.get("Space-In-Value"), None)

