#!/usr/bin/env python
# -*- coding: utf-8 -*-
## ---------------------------------------------------------------------
##
## Copyright (c) 2007-2013 Basho Technologies, Inc.  All Rights Reserved.
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
import os, httplib2, json, unittest, uuid, hashlib, base64
from file_generator import FileGenerator

import boto3
from botocore.client import Config
import botocore

# suppress harmless ResourceWarning
import warnings
warnings.simplefilter("ignore", ResourceWarning)


class S3ApiVerificationTestBase(unittest.TestCase):
    host = None
    try:
        port=int(os.environ['CS_HTTP_PORT'])
    except KeyError:
        port=8080

    user1 = None
    user2 = None

    client = None

    def make_client(self, user):
        # setting proxies via config parameter is broken, so:
        os.environ['http_proxy'] = 'http://127.0.0.1:{}'.format(os.environ.get('CS_HTTP_PORT'))

        if os.environ.get('CS_AUTH', 'auth-v4') == 'auth-v4':
            sig_vsn = 'v4'
        else:
            sig_vsn = 'v2'
        config = Config(signature_version = sig_vsn)
        client = boto3.client('s3',
                              use_ssl = False,
                              aws_access_key_id = user['key_id'],
                              aws_secret_access_key = user['key_secret'],
                              config = config)
        client.meta.events.register_first('before-sign.s3.PutBucketPolicy', add_json_header)
        return client


    @classmethod
    def setUpClass(cls):
        cls.host = "127.0.0.1"
        key_id, key_secret, user_id = \
                (os.environ.get('AWS_ACCESS_KEY_ID'),
                 os.environ.get('AWS_SECRET_ACCESS_KEY'),
                 os.environ.get('USER_ID'))
        if not (key_id and key_secret and user_id):
            # Create test user so credentials don't have to be updated
            # for each test setup.
            # TODO: Once changes are in place so users can be deleted, use
            # userX@example.me for email addresses and clean up at the end of
            # the test run.
            cls.user1 = create_user(cls.host, cls.port, "user1", str(uuid.uuid4()) + "@example.me")
        else:
            cls.user1 = {"name": "admin",  # matches the values set in .../tests/rtcs_admin.erl
                         "email": "admin@me.com",
                         "key_id": key_id, "key_secret": key_secret, "id": user_id}

        cls.user2 = create_user(cls.host, cls.port, "user2", str(uuid.uuid4()) + "@example.me")
        cls.bucket_name = str(uuid.uuid4())
        cls.key_name = str(uuid.uuid4())
        cls.data = mineCoins()

        warnings.simplefilter("ignore", ResourceWarning)

    def setUp(self):
        self.client = self.make_client(self.user1)

    def tearDown(self):
        True # del self.client # doesn't help to prevent ResourceWarning exception (there's a filter trick for that)


    def createBucket(self):
        return self.client.create_bucket(Bucket = self.bucket_name)

    def deleteBucket(self):
        return self.client.delete_bucket(Bucket = self.bucket_name)

    def listBuckets(self):
        return [b['Name'] for b in self.client.list_buckets()['Buckets']]

    def listKeys(self):
        return [k['Key'] for k in self.client.list_objects_v2(Bucket = self.bucket_name).get('Contents', [])]

    def putObject(self, key = None, value = None, metadata = {}):
        if key is None:
            key = self.key_name
        if value is None:
            value = self.data
        return self.client.put_object(Bucket = self.bucket_name,
                                      Key = key,
                                      Body = value,
                                      Metadata = metadata)

    def getObject(self, key = None):
        if key is None:
            key = self.key_name
        return self.client.get_object(Bucket = self.bucket_name,
                                      Key = key)['Body'].read()
    def deleteObject(self, key = None):
        if key is None:
            key = self.key_name
        return self.client.delete_object(Bucket = self.bucket_name,
                                         Key = key)

    def verifyDictListsIdentical(self, cc1, cc2):
        [self.assertIn(c, cc1) for c in cc2]
        [self.assertIn(c, cc2) for c in cc1]

    def upload_multipart(self, key, parts_list,
                         metadata = {}, acl = None):
        pp = {'Bucket': self.bucket_name,
              'Key': key,
              'Metadata': metadata}
        if acl:
            pp['ACL'] = acl
        upload_id = self.client.create_multipart_upload(**pp)['UploadId']
        etags = []
        for index, val in list(enumerate(parts_list)):
            res = self.client.upload_part(UploadId = upload_id,
                                          Bucket = self.bucket_name,
                                          Key = key,
                                          Body = val,
                                          PartNumber = index + 1)
            etags += [{'ETag': res['ETag'], 'PartNumber': index + 1}]
        result = self.client.complete_multipart_upload(UploadId = upload_id,
                                                       Bucket = self.bucket_name,
                                                       Key = key,
                                                       MultipartUpload = {'Parts': etags})
        return upload_id, result

    def multipart_md5_helper(self, parts, key_suffix=u''):
        key_name = str(uuid.uuid4()) + key_suffix
        expected_md5 = hashlib.md5(bytes(b''.join(parts))).hexdigest()
        self.createBucket()
        upload_id, result = self.upload_multipart(key_name, parts)

        actual_md5 = hashlib.md5(bytes(self.getObject(key_name))).hexdigest()
        self.assertEqual(expected_md5, actual_md5)
        self.assertEqual(key_name, result['Key'])
        return upload_id, result


# this is to inject the right headers for put_bucket_policy call
def add_json_header(request, **kwargs):
    request.headers.add_header('content-type', 'application/json')



def create_user(host, port, name, email):
    os.environ['http_proxy'] = ''
    url = 'http://%s:%d/riak-cs/user' % (host, port)
    conn = httplib2.Http()
    resp, content = conn.request(url, "POST",
                                 headers = {"Content-Type": "application/json"},
                                 body = json.dumps({"email": email, "name": name}))
    conn.close()
    return json.loads(content)

def mineCoins(how_much = 1024):
    with open("/dev/urandom", 'rb') as f:
        return f.read(how_much)



class BasicTests(S3ApiVerificationTestBase):
    def test_auth(self):
        bad_user = json.loads('{"email":"baduser@example.me","display_name":"baduser","name":"user1","key_id":"bad_key","key_secret":"BadSecret","id":"bad_canonical_id"}')
        bad_client = self.make_client(bad_user)
        self.assertRaises(botocore.exceptions.ClientError, bad_client.list_buckets)

    def test_create_bucket(self):
        self.createBucket()
        self.assertIn(self.bucket_name, self.listBuckets())

    def test_put_object(self, key = None):
        if key is None:
            key = self.key_name
        self.createBucket()
        self.putObject(key = key)
        self.assertIn(key, self.listKeys())
        self.assertEqual(self.data, self.getObject(key = key))

    def test_put_object_with_trailing_slash(self):
        #boto3.set_stream_logger('')
        self.test_put_object(self.key_name + '/')

    def test_delete_object(self):
        self.createBucket()
        self.putObject()
        self.assertIn(self.key_name, self.listKeys())
        self.deleteObject()
        self.assertNotIn(self.key_name, self.listKeys())
        self.assertRaises(self.client.exceptions.NoSuchKey,
                          lambda: self.client.get_object(Bucket = self.bucket_name,
                                                         Key = self.key_name).get('Body').read())


    def test_delete_objects(self):
        bucket = self.createBucket()
        keys = ['0', '1', u'Unicodeあいうえお', '2', 'multiple   spaces']
        values = [mineCoins() for _ in range(1, 4)]
        kvs = zip(keys, values)
        for k,v in kvs:
            self.putObject(key = k, value = v)

        got_keys = self.listKeys()
        self.assertEqual(keys.sort(), got_keys.sort())

        result = self.client.delete_objects(Bucket = self.bucket_name,
                                            Delete = {'Objects': [{'Key': k} for k in keys]})

        self.assertEqual(keys, [k['Key'] for k in result['Deleted']])
        self.assertEqual([], result.get('Errors', []))

        self.assertRaises(self.client.exceptions.NoSuchKey,
                          lambda: self.client.get_object(Bucket = self.bucket_name,
                                                         Key = keys[0]).get('Body').read())

    def test_delete_bucket(self):
        self.createBucket()
        self.assertIn(self.bucket_name, self.listBuckets())
        self.deleteBucket()
        self.assertNotIn(self.bucket_name, self.listBuckets())

    def test_get_bucket_acl(self):
        self.createBucket()
        res = self.client.get_bucket_acl(Bucket = self.bucket_name)
        self.assertEqual(res['Owner'], {'DisplayName': 'admin', 'ID': self.user1['id']})
        self.verifyDictListsIdentical(res['Grants'],
                                      [userAcl(self.user1, 'FULL_CONTROL')])

    def test_set_bucket_acl(self):
        self.createBucket()
        self.client.put_bucket_acl(Bucket = self.bucket_name,
                                   ACL = 'public-read')
        res = self.client.get_bucket_acl(Bucket = self.bucket_name)
        self.assertEqual(res['Owner']['DisplayName'], self.user1['name'])
        self.assertEqual(res['Owner']['ID'], self.user1['id'])
        self.verifyDictListsIdentical(res['Grants'],
                                      [publicAcl('READ'), userAcl(self.user1, 'FULL_CONTROL')])

    def test_get_object_acl(self):
        self.createBucket()
        self.putObject()
        res = self.client.get_object_acl(Bucket = self.bucket_name,
                                         Key = self.key_name)
        self.assertEqual(res['Grants'], [userAcl(self.user1, 'FULL_CONTROL')])

    def test_set_object_acl(self):
        self.createBucket()
        self.putObject()
        self.client.put_object_acl(Bucket = self.bucket_name,
                                   Key = self.key_name,
                                   ACL = 'public-read')
        res = self.client.get_object_acl(Bucket = self.bucket_name,
                                         Key = self.key_name)
        self.verifyDictListsIdentical(res['Grants'],
                                      [publicAcl('READ'), userAcl(self.user1, 'FULL_CONTROL')])

def userAcl(user, permission):
    return {'Grantee': {'DisplayName': user['name'],
                        'ID': user['id'],
                        'Type': 'CanonicalUser'},
            'Permission': permission}
def publicAcl(permission):
    return {'Grantee': {'Type': 'Group',
                        'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
            'Permission': permission}



class MultiPartUploadTests(S3ApiVerificationTestBase):
    def test_small_strings_upload_1(self):
        parts = [b'this is part one', b'part two is just a rewording',
                 b'surprise that part three is pretty much the same',
                 b'and the last part is number four']
        self.multipart_md5_helper(parts)

    def test_small_strings_upload_2(self):
        parts = [b'just one lonely part']
        self.multipart_md5_helper(parts)

    def test_small_strings_upload_3(self):
        parts = [uuid.uuid4().bytes for _ in range(100)]
        self.multipart_md5_helper(parts)

    def test_acl_is_set(self):
        parts = [uuid.uuid4().bytes for _ in range(5)]
        key_name = str(uuid.uuid4())
        expected_md5 = hashlib.md5(bytes(b''.join(parts))).hexdigest()
        self.createBucket()
        self.upload_multipart(key_name, parts,
                              acl = 'public-read')
        actual_md5 = hashlib.md5(bytes(self.getObject(key_name))).hexdigest()
        self.assertEqual(expected_md5, actual_md5)
        res = self.client.get_object_acl(Bucket = self.bucket_name,
                                         Key = key_name)
        self.assertEqual(res['Owner']['DisplayName'], self.user1['name'])
        self.assertEqual(res['Owner']['ID'], self.user1['id'])
        self.verifyDictListsIdentical(res['Grants'],
                                      [publicAcl('READ'), userAcl(self.user1, 'FULL_CONTROL')])

    def test_standard_storage_class(self):
        self.createBucket()
        key_name = 'test_standard_storage_class'
        self.client.create_multipart_upload(Bucket = self.bucket_name,
                                            Key = self.key_name)
        uploads = self.client.list_multipart_uploads(Bucket = self.bucket_name)['Uploads']
        for u in uploads:
            self.assertEqual(u['StorageClass'], 'STANDARD')
        self.assertTrue(True)

    def test_upload_japanese_key(self):
        parts = [b'this is part one', b'part two is just a rewording',
                 b'surprise that part three is pretty much the same',
                 b'and the last part is number four']
        self.multipart_md5_helper(parts, key_suffix=u'日本語サフィックス')

    def test_list_japanese_key(self):
        self.createBucket()
        key_name = u'test_日本語キーのリスト'
        self.client.create_multipart_upload(Bucket = self.bucket_name,
                                            Key = key_name)
        uploads = self.client.list_multipart_uploads(Bucket = self.bucket_name)['Uploads']
        for u in uploads:
            self.assertEqual(u['Key'], key_name)
        self.assertTrue(True)



class FileGenTest(unittest.TestCase):
    def test_read_twice(self):
        # Read 2KB file and reset (seek to the head) and re-read 2KB
        num_kb = 2
        f = kb_file_gen(num_kb)

        first1 = f.read(1024)
        self.assertEqual(1024, len(first1))
        first2 = f.read(1024)
        self.assertEqual(1024, len(first2))
        self.assertEqual(2048, f.pos)
        self.assertEqual(b'', f.read(1))
        self.assertEqual(b'', f.read(1))
        self.assertEqual(2048, f.pos)

        f.seek(0)
        self.assertEqual(0, f.pos)
        second1 = f.read(1024)
        self.assertEqual(1024, len(first1))
        second2 = f.read(1024)
        self.assertEqual(1024, len(second2))
        self.assertEqual(2048, f.pos)
        self.assertEqual(b'', f.read(1))
        self.assertEqual(b'', f.read(1))


class LargerFileUploadTest(S3ApiVerificationTestBase):
    "Larger, regular key uploads"

    def upload_helper(self, num_kilobytes):
        key_name = str(uuid.uuid4())
        bucket = self.createBucket()
        md5_expected = md5_from_file(kb_file_gen(num_kilobytes))
        file_obj = kb_file_gen(num_kilobytes)
        self.putObject(key_name, file_obj)
        got_object = self.client.get_object(Bucket = self.bucket_name,
                                            Key = key_name)
        actual_md5 = hashlib.md5(bytes(got_object['Body'].read())).hexdigest()
        self.assertEqual(md5_expected, actual_md5)
        self.assertEqual(md5_expected, remove_double_quotes(got_object['ETag']))

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


class LargerMultipartFileUploadTest(S3ApiVerificationTestBase):
    """
    Larger, multipart file uploads - to pass this test,
    requires '{enforce_multipart_part_size, false},' entry at riak_cs's app.config
    """

    def upload_parts_helper(self, zipped_parts_and_md5s, expected_md5):
        self.createBucket()
        key_name = str(uuid.uuid4())
        upload_id = self.client.create_multipart_upload(Bucket = self.bucket_name,
                                                        Key = key_name)['UploadId']
        etags = []
        for idx, (part, md5_of_part) in enumerate(zipped_parts_and_md5s):
            res = self.client.upload_part(UploadId = upload_id,
                                          Bucket = self.bucket_name,
                                          Key = key_name,
                                          Body = part,
                                          PartNumber = idx + 1)
            self.assertEqual(res['ETag'], '"' + md5_of_part + '"')
            etags += [{'ETag': res['ETag'], 'PartNumber': idx + 1}]
        self.client.complete_multipart_upload(UploadId = upload_id,
                                              Bucket = self.bucket_name,
                                              Key = key_name,
                                              MultipartUpload = {'Parts': etags})
        actual_md5 = hashlib.md5(bytes(self.getObject(key_name))).hexdigest()
        self.assertEqual(expected_md5, actual_md5)

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

class UnicodeNamedObjectTest(S3ApiVerificationTestBase):
    "test to check unicode object name works"
    utf8_key_name = u"utf8ファイル名.txt"
    #                     ^^^^^^^^^ filename in Japanese

    def test_unicode_object(self):
        self.createBucket()
        key = UnicodeNamedObjectTest.utf8_key_name
        self.putObject(key = key)
        self.assertEqual(self.getObject(key = key), self.data)
        self.assertIn(key, self.listKeys())

    def test_delete_object(self):
        self.createBucket()
        key = UnicodeNamedObjectTest.utf8_key_name
        self.putObject(key = key)
        self.deleteObject(key = key)
        self.assertNotIn(key, self.listKeys())


class BucketPolicyTest(S3ApiVerificationTestBase):
    "test bucket policy"

    def test_no_policy(self):
        self.createBucket()
        self.client.delete_bucket_policy(Bucket = self.bucket_name)
        try:
            self.client.get_bucket_policy(Bucket = self.bucket_name)
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'NoSuchBucketPolicy')
        else:
            self.fail()

    def create_bucket_and_set_policy(self, policy):
        self.createBucket()
        self.client.put_bucket_policy(Bucket = self.bucket_name,
                                      Policy = json.dumps(policy))

    def test_put_policy_invalid_ip(self):
        policy = {
            "Version":"2020-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:GetObjectAcl","s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % self.bucket_name,
                    "Condition":{"IpAddress":{"aws:SourceIp":"0"}}
                 }
            ]
        }
        try:
            self.create_bucket_and_set_policy(policy)
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'MalformedPolicy')

    def test_put_policy(self):
        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:GetObjectAcl","s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % self.bucket_name,
                    "Condition":{"IpAddress":{"aws:SourceIp":"127.0.0.1/32"}}
                 }
            ]
        }
        self.create_bucket_and_set_policy(policy)
        got_policy = self.client.get_bucket_policy(Bucket = self.bucket_name)['Policy']
        self.assertEqual(policy, json.loads(got_policy))

    def test_put_policy_2(self):
        policy = {
            "Version":"2012-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:GetObjectAcl","s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % self.bucket_name,
                    "Condition":{"IpAddress":{"aws:SourceIp":"127.0.0.1/32"}}
                }
            ]
        }
        self.create_bucket_and_set_policy(policy)
        got_policy = self.client.get_bucket_policy(Bucket = self.bucket_name)['Policy']
        self.assertEqual(policy, json.loads(got_policy))

    def test_put_policy_3(self):
        policy = {
            "Version":"somebadversion",
            "Statement":[
                {
                    "Sid":"Stmtaaa",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:GetObjectAcl","s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % self.bucket_name,
                    "Condition":{"IpAddress":{"aws:SourceIp":"127.0.0.1/32"}}
                }
            ]
        }
        try:
            self.create_bucket_and_set_policy(policy)
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'MalformedPolicy')

    def test_ip_addr_policy(self):
        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa",
                    "Effect":"Deny",
                    "Principal":"*",
                    "Action":["s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % self.bucket_name,
                    "Condition":{"IpAddress":{"aws:SourceIp":"%s" % self.host}}
                }
            ]
        }
        self.create_bucket_and_set_policy(policy)

        key_name = str(uuid.uuid4())
        self.putObject(key = key_name)
        try:
            self.getObject(key = key_name)
            self.fail()
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], '404')

        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % self.bucket_name,
                    "Condition":{"IpAddress":{"aws:SourceIp":"%s" % self.host}}
                }
            ]
        }
        self.client.put_bucket_policy(Bucket = self.bucket_name,
                                      Policy = json.dumps(policy))
        self.getObject(key = key_name) ## throws nothing


    def test_invalid_transport_addr_policy(self):
        self.createBucket()
        key_name = str(uuid.uuid4())
        self.putObject(key = key_name)

        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa0",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % self.bucket_name,
                    "Condition":{"Bool":{"aws:SecureTransport":"wat"}}
                }
            ]
        }
        try:
            self.client.put_bucket_policy(Bucket = self.bucket_name,
                                          Policy = json.dumps(policy))
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'MalformedPolicy')

    def test_transport_addr_policy(self):
        self.createBucket()
        key_name = str(uuid.uuid4())
        self.putObject(key = key_name)

        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa0",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % self.bucket_name,
                    "Condition":{"Bool":{"aws:SecureTransport":False}}
                }
            ]
        }
        self.client.put_bucket_policy(Bucket = self.bucket_name,
                                      Policy = json.dumps(policy))
        self.assertEqual(self.getObject(key = key_name), self.data)

        ## policy accepts anyone who comes with http
        os.environ['http_proxy'] = ''
        conn = httplib2.Http()
        resp, content = conn.request('http://%s:%d/%s' % (self.host, self.port, key_name), "GET",
                                     headers = {"Host": "%s.s3.amazonaws.com" % self.bucket_name})
        conn.close()
        self.assertEqual(resp['status'], '200')
        self.assertEqual(content, self.getObject(key = key_name))

        ## anyone without https may not do any operation
        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa0",
                    "Effect":"Deny",
                    "Principal":"*",
                    "Action":"*",
                    "Resource":"arn:aws:s3:::%s/*" % self.bucket_name,
                    "Condition":{"Bool":{"aws:SecureTransport":False}}
                 }
            ]
        }
        self.client.put_bucket_policy(Bucket = self.bucket_name,
                                      Policy = json.dumps(policy))

        os.environ['http_proxy'] = ''
        conn = httplib2.Http()
        resp, content = conn.request('http://%s:%d/%s' % (self.host, self.port, key_name), "GET",
                                     headers = {"Host": "%s.s3.amazonaws.com" % self.bucket_name})
        conn.close()
        self.assertEqual(resp['status'], '403')


class MultipartUploadTestsUnderPolicy(S3ApiVerificationTestBase):

    def test_small_strings_upload_1(self):
        self.createBucket()
        parts = [b'this is part one', b'part two is just a rewording',
                 b'surprise that part three is pretty much the same',
                 b'and the last part is number four']
        expected_md5 = hashlib.md5(b''.join(parts)).hexdigest()

        key_name = str(uuid.uuid4())

        ## anyone may PUT this object
        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa0",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:PutObject"],
                    "Resource":"arn:aws:s3:::%s/*" % self.bucket_name,
                    "Condition":{"Bool":{"aws:SecureTransport":False}}
                 }
            ]}
        self.client.put_bucket_policy(Bucket = self.bucket_name,
                                      Policy = json.dumps(policy))
        upload_id, result = self.upload_multipart(key_name, parts)
        actual_md5 = hashlib.md5(bytes(self.getObject(key_name))).hexdigest()
        self.assertEqual(expected_md5, actual_md5)

        ## anyone without https may not do any operation
        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa0",
                    "Effect":"Deny",
                    "Principal":"*",
                    "Action":["s3:PutObject"],
                    "Resource":"arn:aws:s3:::%s/*" % self.bucket_name,
                    "Condition":{"Bool":{"aws:SecureTransport":False}}
                }
            ]
        }
        self.client.put_bucket_policy(Bucket = self.bucket_name,
                                      Policy = json.dumps(policy))
        try:
            self.upload_multipart(key_name, parts)
            self.fail()
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'AccessDenied')

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
        key_name = str(uuid.uuid4())
        self.createBucket()
        self.client.put_object(Bucket = self.bucket_name,
                               Key = key_name,
                               Body = "test_normal_object_metadata",
                               Metadata = self.metadata)
        self.assert_metadata(key_name)
        self.change_metadata(key_name)
        self.assert_updated_metadata(key_name)

    def test_mp_object_metadata(self):
        key_name = str(uuid.uuid4())
        bucket = self.createBucket()
        upload = self.upload_multipart(key_name, [b"part1"],
                                       metadata = self.metadata)
        self.assert_metadata(key_name)
        self.change_metadata(key_name)
        self.assert_updated_metadata(key_name)

    def assert_metadata(self, key_name):
        res = self.client.get_object(Bucket = self.bucket_name,
                                     Key = key_name)

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

    def change_metadata(self, key_name):
        self.client.copy_object(Bucket = self.bucket_name,
                                Key = key_name,
                                CopySource = "%s/%s" % (self.bucket_name, key_name),
                                MetadataDirective = 'REPLACE',
                                Metadata = self.updated_metadata)

    def assert_updated_metadata(self, key_name):
        res = self.client.get_object(Bucket = self.bucket_name,
                                     Key = key_name)

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


class ContentMd5Test(S3ApiVerificationTestBase):
    def test_catches_bad_md5(self):
        key_name = str(uuid.uuid4())
        bucket = self.createBucket()
        s = b'not the real content'
        bad_md5 = hashlib.md5(s).hexdigest()
        try:
            self.client.put_object(Bucket = self.bucket_name,
                                   Key = key_name,
                                   Body = 'this is different from the md5 we calculated',
                                   ContentMD5 = bad_md5)
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'InvalidDigest')


    def test_bad_md5_leaves_old_object_alone(self):
        # Github #705 Regression test:
        # Make sure that overwriting an object using a bad md5
        # simply leaves the old version in place.
        key_name = str(uuid.uuid4())
        self.createBucket()
        value = b'good value'
        self.client.put_object(Bucket = self.bucket_name,
                               Key = key_name,
                               Body = value)
        bad_value = b'not the real content'
        bad_md5 = hashlib.md5(bad_value).hexdigest()
        try:
            self.client.put_object(Bucket = self.bucket_name,
                                   Key = key_name,
                                   Body = 'this is different from the md5 we calculated',
                                   ContentMD5 = bad_md5)
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'InvalidDigest')

        self.assertEqual(self.getObject(key = key_name), value)

class SimpleCopyTest(S3ApiVerificationTestBase):

    def test_put_copy_object(self):
        self.createBucket()
        self.putObject()

        target_bucket_name = str(uuid.uuid4())
        target_key_name = str(uuid.uuid4())
        self.client.create_bucket(Bucket = target_bucket_name)

        self.client.copy_object(Bucket = target_bucket_name,
                                CopySource = '%s/%s' % (self.bucket_name, self.key_name),
                                Key = target_key_name)

        self.assertEqual(self.client.get_object(Bucket = self.bucket_name, Key = self.key_name)['Body'].read(),
                         self.data)
        self.assertEqual(self.client.get_object(Bucket = self.bucket_name, Key = self.key_name)['Body'].read(),
                         self.client.get_object(Bucket = target_bucket_name, Key = target_key_name)['Body'].read())
        self.assertIn(target_key_name,
                      [k['Key'] for k in self.client.list_objects_v2(Bucket = target_bucket_name).get('Contents', [])])

    def test_put_copy_object_from_mp(self):
        self.createBucket()
        upload_id, result = self.upload_multipart(self.key_name, [self.data])

        target_bucket_name = str(uuid.uuid4())
        target_key_name = str(uuid.uuid4())
        target_bucket = self.client.create_bucket(Bucket = target_bucket_name)

        self.client.copy_object(Bucket = target_bucket_name,
                                CopySource = '%s/%s' % (self.bucket_name, self.key_name),
                                Key = target_key_name)

        self.assertEqual(self.client.get_object(Bucket = self.bucket_name, Key = self.key_name)['Body'].read(),
                         self.data)
        self.assertEqual(self.client.get_object(Bucket = self.bucket_name, Key = self.key_name)['Body'].read(),
                         self.client.get_object(Bucket = target_bucket_name, Key = target_key_name)['Body'].read())
        self.assertIn(target_key_name,
                      [k['Key'] for k in self.client.list_objects_v2(Bucket = target_bucket_name).get('Contents', [])])

    def test_upload_part_from_non_mp(self):
        self.createBucket()
        self.putObject()

        target_bucket_name = str(uuid.uuid4())
        target_key_name = str(uuid.uuid4())
        self.client.create_bucket(Bucket = target_bucket_name)

        start_offset, end_offset = 0, 9
        upload_id = self.client.create_multipart_upload(Bucket = target_bucket_name,
                                                        Key = target_key_name)['UploadId']
        res = self.client.upload_part_copy(Bucket = target_bucket_name,
                                           Key = target_key_name,
                                           PartNumber = 1,
                                           UploadId = upload_id,
                                           CopySource = "%s/%s" % (self.bucket_name, self.key_name),
                                           CopySourceRange = "bytes=%d-%d" % (start_offset, end_offset))
        etags = [{'ETag': res['CopyPartResult']['ETag'], 'PartNumber': 1}]

        self.client.complete_multipart_upload(Bucket = target_bucket_name,
                                              Key = target_key_name,
                                              UploadId = upload_id,
                                              MultipartUpload = {'Parts': etags})

        self.assertEqual(self.data[start_offset:(end_offset+1)],
                         self.client.get_object(Bucket = target_bucket_name,
                                                Key = target_key_name)['Body'].read())

    def test_upload_part_from_mp(self):
        self.createBucket()
        key_name = str(uuid.uuid4())
        upload1_id, result = self.upload_multipart(key_name, [self.data])

        target_bucket_name = str(uuid.uuid4())
        target_bucket = self.client.create_bucket(Bucket = target_bucket_name)

        start_offset, end_offset = 0, 9
        upload2_id = self.client.create_multipart_upload(Bucket = target_bucket_name,
                                                         Key = key_name)['UploadId']
        res = self.client.upload_part_copy(Bucket = target_bucket_name,
                                           Key = key_name,
                                           PartNumber = 1,
                                           UploadId = upload2_id,
                                           CopySource = "%s/%s" % (self.bucket_name, self.key_name),
                                           CopySourceRange = "bytes=%d-%d" % (start_offset, end_offset))
        etags = [{'ETag': res['CopyPartResult']['ETag'], 'PartNumber': 1}]
        self.client.complete_multipart_upload(Bucket = target_bucket_name,
                                              Key = key_name,
                                              UploadId = upload2_id,
                                              MultipartUpload = {'Parts': etags})

        self.assertEqual(self.data[start_offset:(end_offset+1)],
                         self.client.get_object(Bucket = target_bucket_name,
                                                Key = key_name)['Body'].read())

    def test_put_copy_from_non_existing_key_404(self):
        self.createBucket()

        target_bucket_name = str(uuid.uuid4())
        target_key_name = str(uuid.uuid4())
        self.client.create_bucket(Bucket = target_bucket_name)
        try:
            self.client.copy_object(Bucket = target_bucket_name,
                                    Key = target_key_name,
                                    CopySource = '%s/%s' % (self.bucket_name, 'not_existing'))
            self.fail()
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'NoSuchKey')


def one_kb_string():
    "Return a 1KB string of all a's"
    return ''.join(['a' for _ in range(1024)])

def kb_gen_fn(num_kilobytes):
    s = one_kb_string()
    def fn():
        return (s for _ in range(num_kilobytes))
    return fn

def kb_file_gen(num_kilobytes):
    gen_fn = kb_gen_fn(num_kilobytes)
    return FileGenerator(gen_fn, num_kilobytes * 1024)

def mb_file_gen(num_megabytes):
    return kb_file_gen(num_megabytes * 1024)

def md5_from_file(file_object):
    m = hashlib.md5()
    update_md5_from_file(m, file_object)
    return m.hexdigest()

# note the plural
def md5_from_files(file_objects):
    m = hashlib.md5()
    for f in file_objects:
        update_md5_from_file(m, f)
    return m.hexdigest()

def update_md5_from_file(md5_object, file_object):
    "Helper function for calculating the hex md5 of a file-like object"
    go = True
    while go:
        byte = file_object.read(8196)
        if byte:
            md5_object.update(byte)
        else:
            go = False
    return md5_object

def remove_double_quotes(string):
    return string.replace('"', '')


if __name__ == "__main__":
    unittest.main(verbosity=2)
