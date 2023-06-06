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

class MultiPartUploadTests(AmzTestBase):
    def test_small_strings_upload_1(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        parts = [b'this is part one', b'part two is just a rewording',
                 b'surprise that part three is pretty much the same',
                 b'and the last part is number four']
        self.multipart_md5_helper(bucket, parts)
        self.deleteBucket(bucket = bucket)

    def test_small_strings_upload_2(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        parts = [b'just one lonely part']
        self.multipart_md5_helper(bucket, parts)
        self.deleteBucket(bucket = bucket)

    def test_small_strings_upload_3(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        parts = [uuid.uuid4().bytes for _ in range(100)]
        self.multipart_md5_helper(bucket, parts)
        self.deleteBucket(bucket = bucket)

    def test_acl_is_set(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        parts = [uuid.uuid4().bytes for _ in range(5)]
        key = str(uuid.uuid4())
        expected_md5 = hashlib.md5(bytes(b''.join(parts))).hexdigest()
        self.upload_multipart(bucket, key, parts,
                              acl = 'public-read')
        actual_md5 = hashlib.md5(bytes(self.getObject(bucket = bucket,
                                                      key = key))).hexdigest()
        self.assertEqual(expected_md5, actual_md5)
        res = self.s3_client.get_object_acl(Bucket = bucket,
                                            Key = key)
        self.assertEqual(res['Owner']['DisplayName'], self.user1['name'])
        self.assertEqual(res['Owner']['ID'], self.user1['id'])
        self.verifyDictListsIdentical(res['Grants'],
                                      [publicAcl('READ'), userAcl(self.user1, 'FULL_CONTROL')])
        self.deleteBucket(bucket = bucket)

    def test_standard_storage_class(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        key = 'test_standard_storage_class'
        self.s3_client.create_multipart_upload(Bucket = bucket,
                                               Key = key)
        uploads = self.s3_client.list_multipart_uploads(Bucket = bucket)['Uploads']
        for u in uploads:
            self.assertEqual(u['StorageClass'], 'STANDARD')
        self.deleteBucket(bucket = bucket)

    def test_upload_japanese_key(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        parts = [b'this is part one', b'part two is just a rewording',
                 b'surprise that part three is pretty much the same',
                 b'and the last part is number four']
        self.multipart_md5_helper(bucket, parts, key_suffix=u'日本語サフィックス')
        self.deleteBucket(bucket = bucket)

    def test_list_japanese_key(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        key = u'test_日本語キーのリスト'
        self.s3_client.create_multipart_upload(Bucket = bucket,
                                               Key = key)
        uploads = self.s3_client.list_multipart_uploads(Bucket = bucket)['Uploads']
        for u in uploads:
            self.assertEqual(u['Key'], key)
        self.deleteBucket(bucket = bucket)


class LargerMultipartFileUploadTest(AmzTestBase):
    """
    Larger, multipart file uploads - to pass this test,
    requires '{enforce_multipart_part_size, false},' entry at riak_cs's app.config
    """

    def upload_parts_helper(self, zipped_parts_and_md5s, expected_md5):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        upload_id = self.s3_client.create_multipart_upload(Bucket = bucket,
                                                           Key = self.default_key)['UploadId']
        etags = []
        for idx, (part, md5_of_part) in enumerate(zipped_parts_and_md5s):
            res = self.s3_client.upload_part(UploadId = upload_id,
                                             Bucket = bucket,
                                             Key = self.default_key,
                                             Body = part,
                                             PartNumber = idx + 1)
            self.assertEqual(res['ETag'], '"' + md5_of_part + '"')
            etags += [{'ETag': res['ETag'], 'PartNumber': idx + 1}]
        self.s3_client.complete_multipart_upload(UploadId = upload_id,
                                                 Bucket = bucket,
                                                 Key = self.default_key,
                                                 MultipartUpload = {'Parts': etags})
        actual_md5 = hashlib.md5(bytes(self.getObject(bucket = bucket))).hexdigest()
        self.assertEqual(expected_md5, actual_md5)
        self.deleteBucket(bucket = bucket)

    def from_mb_list(self, mb_list):
        md5_list = [md5_from_file(mb_file_gen(m)) for m in mb_list]
        expected_md5 = md5_from_files([mb_file_gen(m) for m in mb_list])
        parts = [mb_file_gen(m) for m in mb_list]
        self.upload_parts_helper(zip(parts, md5_list), expected_md5)

    def test_upload_1(self):
        mb_list = [5, 6, 5, 7, 8, 9]
        self.from_mb_list(mb_list)

    def test_upload_2(self):
        mb_list = [10, 11, 5, 7, 9, 14, 12]
        self.from_mb_list(mb_list)

    def test_upload_3(self):
        mb_list = [15, 14, 13, 12, 11, 10]
        self.from_mb_list(mb_list)

