#!/usr/bin/env python
# -*- coding: utf-8 -*-
## ---------------------------------------------------------------------
##
## Copyright (c) 2007-2013 Basho Technologies, Inc.  All Rights Reserved.
##               2021-2023 TI Tokyo    All Rights Reserved.
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
import botocore, json, uuid

class BasicTests(AmzTestBase):
    def test_auth(self):
        bad_user = json.loads('{"email":"baduser@example.me","display_name":"baduser","name":"user1","key_id":"bad_key","key_secret":"BadSecret","id":"bad_canonical_id"}')
        bad_client, _, _ = self.make_clients(bad_user)
        self.assertRaises(botocore.exceptions.ClientError, bad_client.list_buckets)

    def test_create_bucket(self):
        #boto3.set_stream_logger('')
        self.createBucket()
        self.assertIn(self.default_bucket, self.listBuckets())
        self.deleteBucket()

    def test_put_object(self, key = None):
        bucket = str(uuid.uuid4())
        if key is None:
            key = self.default_key
        self.createBucket(bucket = bucket)
        self.putObject(bucket = bucket, key = key)
        self.assertIn(key, self.listKeys(bucket = bucket))
        self.assertEqual(self.data, self.getObject(bucket = bucket, key = key))
        self.deleteBucket(bucket = bucket)

    def test_put_object_with_trailing_slash(self):
        self.test_put_object(self.default_key + '/')

    def test_delete_object(self):
        self.createBucket()
        self.putObject()
        self.assertIn(self.default_key, self.listKeys())
        #boto3.set_stream_logger('')
        self.deleteObject()
        self.assertNotIn(self.default_key, self.listKeys())
        self.assertRaises(self.s3_client.exceptions.NoSuchKey,
                          lambda: self.s3_client.get_object(Bucket = self.default_bucket,
                                                            Key = self.default_key).get('Body').read())
        self.deleteBucket()


    def test_delete_objects(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        keys = ['0', '1', u'Unicodeあいうえお', '2', 'multiple   spaces']
        values = [mineCoins() for _ in range(1, 4)]
        kvs = zip(keys, values)
        for k,v in kvs:
            self.putObject(bucket = bucket, key = k, value = v)

        got_keys = self.listKeys(bucket = bucket)
        self.assertEqual(keys.sort(), got_keys.sort())

        result = self.s3_client.delete_objects(Bucket = bucket,
                                               Delete = {'Objects': [{'Key': k} for k in keys]})

        self.assertEqual(keys, [k['Key'] for k in result['Deleted']])
        self.assertEqual([], result.get('Errors', []))

        self.assertRaises(self.s3_client.exceptions.NoSuchKey,
                          lambda: self.s3_client.get_object(Bucket = bucket,
                                                            Key = keys[0]).get('Body').read())
        self.deleteBucket(bucket = bucket)

    def test_delete_bucket(self):
        self.createBucket()
        self.assertIn(self.default_bucket, self.listBuckets())
        #boto3.set_stream_logger('')
        self.deleteBucket()
        self.assertNotIn(self.default_bucket, self.listBuckets())

    def test_get_bucket_acl(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        res = self.s3_client.get_bucket_acl(Bucket = bucket)
        self.assertEqual(res['Owner'], {'DisplayName': 'admin', 'ID': self.user1['id']})
        self.verifyDictListsIdentical(res['Grants'],
                                      [userAcl(self.user1, 'FULL_CONTROL')])
        self.deleteBucket(bucket = bucket)

    def test_set_bucket_acl(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        self.s3_client.put_bucket_acl(Bucket = bucket,
                                   ACL = 'public-read')
        res = self.s3_client.get_bucket_acl(Bucket = bucket)
        self.assertEqual(res['Owner']['DisplayName'], self.user1['name'])
        self.assertEqual(res['Owner']['ID'], self.user1['id'])
        self.verifyDictListsIdentical(res['Grants'],
                                      [publicAcl('READ'), userAcl(self.user1, 'FULL_CONTROL')])
        self.deleteBucket(bucket = bucket)

    def test_get_object_acl(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        self.putObject(bucket = bucket)
        res = self.s3_client.get_object_acl(Bucket = bucket,
                                            Key = self.default_key)
        self.assertEqual(res['Grants'], [userAcl(self.user1, 'FULL_CONTROL')])
        self.deleteBucket(bucket = bucket)

    def test_set_object_acl(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        self.putObject(bucket = bucket)
        self.s3_client.put_object_acl(Bucket = bucket,
                                      Key = self.default_key,
                                      ACL = 'public-read')
        res = self.s3_client.get_object_acl(Bucket = bucket,
                                            Key = self.default_key)
        self.verifyDictListsIdentical(res['Grants'],
                                      [publicAcl('READ'), userAcl(self.user1, 'FULL_CONTROL')])
        self.deleteBucket(bucket = bucket)


class SimpleCopyTest(AmzTestBase):

    def test_put_copy_object(self):
        src_bucket = str(uuid.uuid4())
        self.createBucket(bucket = src_bucket)
        self.putObject(bucket = src_bucket)

        target_bucket = str(uuid.uuid4())
        self.createBucket(bucket = target_bucket)

        self.s3_client.copy_object(Bucket = target_bucket,
                                   CopySource = '%s/%s' % (src_bucket, self.default_key),
                                   Key = self.default_key)

        self.assertEqual(self.getObject(bucket = src_bucket), self.data)
        self.assertEqual(self.getObject(bucket = target_bucket), self.data)
        self.assertIn(self.default_key, self.listKeys(bucket = target_bucket))

        self.deleteBucket(bucket = src_bucket)
        self.deleteBucket(bucket = target_bucket)

    def test_put_copy_object_from_mp(self):
        #boto3.set_stream_logger('')
        src_bucket = str(uuid.uuid4())
        self.createBucket(bucket = src_bucket)
        upload_id, result = self.upload_multipart(src_bucket, self.default_key, [self.data])

        target_bucket = str(uuid.uuid4())
        self.createBucket(bucket = target_bucket)

        self.s3_client.copy_object(Bucket = target_bucket,
                                   CopySource = '%s/%s' % (src_bucket, self.default_key),
                                   Key = self.default_key)

        self.assertEqual(self.getObject(bucket = src_bucket), self.data)
        self.assertEqual(self.getObject(bucket = target_bucket), self.data)
        self.assertIn(self.default_key, self.listKeys(bucket = target_bucket))

        self.deleteBucket(bucket = src_bucket)
        self.deleteBucket(bucket = target_bucket)

    def test_upload_part_from_non_mp(self):
        src_bucket = str(uuid.uuid4())
        self.createBucket(bucket = src_bucket)
        self.putObject(bucket = src_bucket)

        target_bucket = str(uuid.uuid4())
        self.createBucket(bucket = target_bucket)

        start_offset, end_offset = 0, 9
        upload_id = self.s3_client.create_multipart_upload(Bucket = target_bucket,
                                                        Key = self.default_key)['UploadId']
        res = self.s3_client.upload_part_copy(Bucket = target_bucket,
                                              Key = self.default_key,
                                              PartNumber = 1,
                                              UploadId = upload_id,
                                              CopySource = "%s/%s" % (src_bucket, self.default_key),
                                              CopySourceRange = "bytes=%d-%d" % (start_offset, end_offset))
        etags = [{'ETag': res['CopyPartResult']['ETag'], 'PartNumber': 1}]

        self.s3_client.complete_multipart_upload(Bucket = target_bucket,
                                                 Key = self.default_key,
                                                 UploadId = upload_id,
                                                 MultipartUpload = {'Parts': etags})

        self.assertEqual(self.data[start_offset:(end_offset+1)],
                         self.getObject(bucket = target_bucket))
        self.deleteBucket(bucket = src_bucket)
        self.deleteBucket(bucket = target_bucket)

    def test_upload_part_from_mp(self):
        src_bucket = str(uuid.uuid4())
        self.createBucket(bucket = src_bucket)
        upload1_id, result = self.upload_multipart(src_bucket, self.default_key, [self.data])

        target_bucket = str(uuid.uuid4())
        self.createBucket(bucket = target_bucket)

        start_offset, end_offset = 0, 9
        upload2_id = self.s3_client.create_multipart_upload(Bucket = target_bucket,
                                                            Key = self.default_key)['UploadId']
        res = self.s3_client.upload_part_copy(Bucket = target_bucket,
                                              Key = self.default_key,
                                              PartNumber = 1,
                                              UploadId = upload2_id,
                                              CopySource = "%s/%s" % (src_bucket, self.default_key),
                                              CopySourceRange = "bytes=%d-%d" % (start_offset, end_offset))
        etags = [{'ETag': res['CopyPartResult']['ETag'], 'PartNumber': 1}]
        self.s3_client.complete_multipart_upload(Bucket = target_bucket,
                                                 Key = self.default_key,
                                                 UploadId = upload2_id,
                                                 MultipartUpload = {'Parts': etags})

        self.assertEqual(self.data[start_offset:(end_offset+1)],
                         self.getObject(bucket = target_bucket))

        self.deleteBucket(bucket = src_bucket)
        self.deleteBucket(bucket = target_bucket)

    def test_put_copy_from_non_existing_key_404(self):
        src_bucket = str(uuid.uuid4())
        self.createBucket(bucket = src_bucket)

        target_bucket = str(uuid.uuid4())
        self.createBucket(bucket = target_bucket)
        try:
            self.s3_client.copy_object(Bucket = target_bucket,
                                       Key = self.default_key,
                                       CopySource = '%s/%s' % (src_bucket, 'not_existing'))
            self.fail()
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'NoSuchKey')

        self.deleteBucket(bucket = src_bucket)
        self.deleteBucket(bucket = target_bucket)


class LargerFileUploadTest(AmzTestBase):
    "Larger, regular key uploads"

    def upload_helper(self, num_kilobytes):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        md5_expected = md5_from_file(kb_file_gen(num_kilobytes))
        file_obj = kb_file_gen(num_kilobytes)
        self.putObject(bucket = bucket,
                       value = file_obj)
        got_object = self.s3_client.get_object(Bucket = bucket, Key = self.default_key)
        actual_md5 = hashlib.md5(bytes(got_object['Body'].read())).hexdigest()
        self.assertEqual(md5_expected, actual_md5)
        self.assertEqual(md5_expected, remove_double_quotes(got_object['ETag']))
        self.deleteBucket(bucket = bucket)

    def test_1kb(self):
        return self.upload_helper(1)

    def test_2kb(self):
        return self.upload_helper(2)

    def test_256kb(self):
        return self.upload_helper(256)

    def test_512kb(self):
        return self.upload_helper(512)

    def test_1mb(self):
        return self.upload_helper(1 * 1024)

    def test_4mb(self):
        return self.upload_helper(4 * 1024)

    def test_8mb(self):
        return self.upload_helper(8 * 1024)

    def test_16mb(self):
        return self.upload_helper(16 * 1024)

    def test_32mb(self):
        return self.upload_helper(32 * 1024)



class UnicodeNamedObjectTest(AmzTestBase):
    "test to check unicode object name works"
    utf8_default_key = u"utf8ファイル名.txt"
    #                     ^^^^^^^^^ filename in Japanese

    def test_unicode_object(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        key = UnicodeNamedObjectTest.utf8_default_key
        self.putObject(bucket = bucket)
        self.assertEqual(self.getObject(bucket = bucket), self.data)
        self.assertIn(self.default_key, self.listKeys(bucket = bucket))
        self.deleteBucket(bucket = bucket)

    def test_delete_object(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        key = UnicodeNamedObjectTest.utf8_default_key
        self.putObject(bucket = bucket)
        self.deleteObject(bucket = bucket)
        self.assertNotIn(key, self.listKeys(bucket = bucket))
        self.deleteBucket(bucket = bucket)



class ContentMd5Test(AmzTestBase):
    def test_catches_bad_md5(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        s = b'not the real content'
        bad_md5 = hashlib.md5(s).hexdigest()
        try:
            self.s3_client.put_object(Bucket = bucket,
                                      Key = self.default_key,
                                      Body = 'this is different from the md5 we calculated',
                                      ContentMD5 = bad_md5)
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'InvalidDigest')
        self.deleteBucket(bucket = bucket)


    def test_bad_md5_leaves_old_object_alone(self):
        # Github #705 Regression test:
        # Make sure that overwriting an object using a bad md5
        # simply leaves the old version in place.
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        value = b'good value'
        self.putObject(bucket = bucket, value = value)
        bad_value = b'not the real content'
        bad_md5 = hashlib.md5(bad_value).hexdigest()
        try:
            self.s3_client.put_object(Bucket = bucket,
                                      Key = self.default_key,
                                      Body = 'this is different from the md5 we calculated',
                                      ContentMD5 = bad_md5)
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'InvalidDigest')
        self.assertEqual(self.getObject(bucket = bucket), value)
        self.deleteBucket(bucket = bucket)
