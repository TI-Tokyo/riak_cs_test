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

import os, httplib2, json, unittest, uuid, hashlib, time
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
        os.environ['http_proxy'] = 'http://127.0.0.1:%d' % (int(os.environ.get('CS_HTTP_PORT')))

        if os.environ.get('CS_AUTH', 'auth-v4') == 'auth-v4':
            sig_vsn = 's3v4'
        else:
            sig_vsn = 's3'
        config = Config(signature_version = sig_vsn)
        client = boto3.client('s3',
                              use_ssl = False,
                              aws_access_key_id = user['key_id'],
                              aws_secret_access_key = user['key_secret'],
                              config = config)
        client.meta.events.register_first('before-sign.s3.PutBucketPolicy', add_json_ctype_header)
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


    def createBucket(self, bucket = None):
        if bucket is None:
            bucket = self.bucket_name
        return self.client.create_bucket(Bucket = bucket)

    def deleteBucket(self, bucket = None):
        if bucket is None:
            bucket = self.bucket_name
        try:
            self.client.delete_bucket(Bucket = bucket)
        except:
            for o in self.listKeys(bucket = bucket):
                self.deleteObject(bucket = bucket, key = o)
            self.client.delete_bucket(Bucket = bucket)

    def listBuckets(self):
        return [b['Name'] for b in self.client.list_buckets()['Buckets']]

    def listKeys(self, bucket = None):
        if bucket is None:
            bucket = self.bucket_name
        return [k['Key'] for k in self.client.list_objects_v2(Bucket = bucket).get('Contents', [])]

    def listObjectVersions(self, bucket = None):
        if bucket is None:
            bucket = self.bucket_name
        vv = self.client.list_object_versions(Bucket = bucket)
        return vv.get('Versions', [])

    def putObject(self, bucket = None, key = None, value = None, metadata = {}):
        if bucket is None:
            bucket = self.bucket_name
        if key is None:
            key = self.key_name
        if value is None:
            value = self.data
        res = self.client.put_object(Bucket = bucket,
                                     Key = key,
                                     Body = value,
                                     Metadata = metadata)
        return res['ResponseMetadata']['HTTPHeaders']['x-amz-version-id']

    def getObject(self, bucket = None, key = None, vsn = None):
        if bucket is None:
            bucket = self.bucket_name
        if key is None:
            key = self.key_name
        if vsn is None:
            vsn = 'null'
        return bytes(self.client.get_object(Bucket = bucket,
                                            Key = key,
                                            VersionId = vsn)['Body'].read())

    def deleteObject(self, bucket = None, key = None, vsn = None):
        if bucket is None:
            bucket = self.bucket_name
        if key is None:
            key = self.key_name
        if vsn is None:
            vsn = 'null'
        return self.client.delete_object(Bucket = bucket,
                                         Key = key,
                                         VersionId = vsn)

    def getBucketVersioning(self, bucket = None):
        ####boto3.set_stream_logger('')
        if bucket is None:
            bucket = self.bucket_name
        return self.client.get_bucket_versioning(Bucket = bucket)['Status']

    def putBucketVersioning(self, status,
                            bucket = None, mfaDelete = None,
                            useSubVersioning = None,
                            canUpdateVersions = None,
                            replSiblings = None):
        if bucket is None:
            bucket = self.bucket_name
        if mfaDelete is None:
            vsnconf = {'Status': status}
        else:
            vsnconf = {'MFADelete': mfaDelete,
                       'Status': status}

        self.client.meta.events.register_first(
            'before-sign.s3.PutBucketVersioning',
            lambda request, **kwargs: add_versioning_headers(request,
                                                             useSubVersioning,
                                                             canUpdateVersions,
                                                             replSiblings,
                                                             **kwargs))
        res = self.client.put_bucket_versioning(Bucket = bucket,
                                                VersioningConfiguration = vsnconf)
        return res

    def verifyDictListsIdentical(self, cc1, cc2):
        [self.assertIn(c, cc1) for c in cc2]
        [self.assertIn(c, cc2) for c in cc1]

    def upload_multipart(self, bucket, key, parts_list,
                         metadata = {}, acl = None):
        pp = {'Bucket': bucket,
              'Key': key,
              'Metadata': metadata}
        if acl:
            pp['ACL'] = acl
        upload_id = self.client.create_multipart_upload(**pp)['UploadId']
        etags = []
        for index, val in list(enumerate(parts_list)):
            res = self.client.upload_part(UploadId = upload_id,
                                          Bucket = bucket,
                                          Key = key,
                                          Body = val,
                                          PartNumber = index + 1)
            etags += [{'ETag': res['ETag'], 'PartNumber': index + 1}]
        result = self.client.complete_multipart_upload(UploadId = upload_id,
                                                       Bucket = bucket,
                                                       Key = key,
                                                       MultipartUpload = {'Parts': etags})
        return upload_id, result

    def multipart_md5_helper(self, bucket, parts, key_suffix = u''):
        key = str(uuid.uuid4()) + key_suffix
        expected_md5 = hashlib.md5(bytes(b''.join(parts))).hexdigest()
        upload_id, result = self.upload_multipart(bucket, key, parts)

        actual_md5 = hashlib.md5(bytes(self.getObject(bucket = bucket,
                                                      key = key))).hexdigest()
        self.assertEqual(expected_md5, actual_md5)
        self.assertEqual(key, result['Key'])
        return upload_id, result


# this is to inject the right headers for put_bucket_policy call
def add_json_ctype_header(request, **kwargs):
    request.headers.add_header('content-type', 'application/json')

def add_versioning_headers(request, useSubVersioning, canUpdateVersions, replSiblings, **kwargs):
    if useSubVersioning is not None:
        request.headers.add_header('x-rcs-versioning-use_subversioning', str(useSubVersioning))
    if canUpdateVersions is not None:
        request.headers.add_header('x-rcs-versioning-can_update_versions', str(canUpdateVersions))
    if replSiblings is not None:
        request.headers.add_header('x-rcs-versioning-repl_siblings', str(replSiblings))


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


def userAcl(user, permission):
    return {'Grantee': {'DisplayName': user['name'],
                        'ID': user['id'],
                        'Type': 'CanonicalUser'},
            'Permission': permission}
def publicAcl(permission):
    return {'Grantee': {'Type': 'Group',
                        'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
            'Permission': permission}



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
