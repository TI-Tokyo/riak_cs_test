#!/usr/bin/env python
# -*- coding: utf-8 -*-
## ---------------------------------------------------------------------
##
## Copyright (c) 2021-2023 TI Tokyo. All Rights Reserved.
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
import unittest
import httplib2, json
import uuid, hashlib, base64
import os, time, tempfile, pathlib, subprocess, re, pprint

class S3CmdException(Exception):
    pass


class S3ApiVerificationTestBase(unittest.TestCase):
    host = None
    port = 8080

    user1 = None
    user2 = None

    tmpdir = None
    scratch = None
    s3cmd_cf = None

    @classmethod
    def setUpClass(cls):
        cls.host = "127.0.0.1"
        try:
            cls.port=int(os.environ['CS_HTTP_PORT'])
        except:
            pass

        (key_id, key_secret, user_id) = \
            (os.environ.get('AWS_ACCESS_KEY_ID'),
             os.environ.get('AWS_SECRET_ACCESS_KEY'),
             os.environ.get('USER_ID'))
        if not (key_id and key_secret and user_id):
            # Create test user so credentials don't have to be updated
            # for each test setup.
            cls.user1 = create_user(cls.host, cls.port, "user1", str(uuid.uuid4()) + "@example.me")
        else:
            cls.user1 = {"name": "admin",  # matches the values set in .../tests/rtcs_admin.erl
                         "email": "admin@me.com",
                         "key_id": key_id, "key_secret": key_secret, "id": user_id}

        cls.tmpdir = tempfile.TemporaryDirectory(prefix = "fafa")
        cls.scratch = cls.tmpdir.name
        cls.s3cmd_cf = "%s/.s3cmd.config" % (cls.scratch)

        with open(cls.s3cmd_cf, mode = "w+") as f:
            config = """[default]
                access_key = %s
                secret_key = %s
                proxy_host = %s
                proxy_port = %d
                use_https = False
                """ % (cls.user1["key_id"], cls.user1["key_secret"], "127.0.0.1", cls.port)
            f.write(config)

        cls.user2 = create_user(cls.host, cls.port, "user2", str(uuid.uuid4()) + "@example.me")
        cls.bucket0 = str(uuid.uuid4())
        cls.key0 = str(uuid.uuid4())
        cls.data0 = mineCoins()

    def setUp(self):
        True

    def tearDown(self):
        True

    def c(self, args):
        os.environ['http_proxy'] = '127.0.0.1:%d' % (self.port)
        args = ["s3cmd", "--config=%s" % (self.s3cmd_cf)] + args
        try:
            mpp("cmd: ", args)
            completed = subprocess.run(args,
                                       capture_output = True,
                                       encoding = "utf8")
            mpp("output: ", completed.stdout)
        except Exception as e:
            mpp("Exception:", e)
        if completed.returncode != 0:
            raise S3CmdException(completed)
        return completed

    def createBucket(self, bucket = None):
        if bucket is None:
            bucket = self.bucket0
        self.c(["mb", "s3://%s" % (bucket)])

    def deleteBucket(self, bucket = None):
        if bucket is None:
            bucket = self.bucket0
        self.c(["rb", "s3://%s" % (bucket)])

    def listBuckets(self):
        out = self.c(["ls", "s3://"])
        return [re.split(".*s3://(.+)", l)[1] for l in str.splitlines(out.stdout)]

    def listKeys(self, bucket = None):
        if bucket is None:
            bucket = self.bucket0
        out = self.c(["ls", "s3://%s" % (bucket)])
        return [re.split(".*s3://" + bucket + "/(.+)", l)[1] for l in str.splitlines(out.stdout)]

    def getObject(self, bucket = None, key = None, extra_args = []):
        if bucket is None:
            bucket = self.bucket0
        if key is None:
            key = self.key0
        fn = "%s/obj" % (self.scratch)
        self.c(["get", "s3://%s/%s" % (bucket, key), fn] + extra_args)
        with open(fn, "rb") as f:
            ret = f.read()
            os.unlink(fn)
            return ret

    def putObject(self, bucket = None, key = None, value = None, extra_args = []):
        if bucket is None:
            bucket = self.bucket0
        if key is None:
            key = self.key0
        if value is None:
            value = self.data0
        fn = "%s/obj" % (self.scratch)
        f = open(fn, "w+b")
        a = f.write(value)
        f.close()
        ret = self.c(["put", fn, "s3://%s/%s" % (bucket, key)] + extra_args)
        os.unlink(fn)

    def deleteObject(self, bucket = None, key = None):
        if bucket is None:
            bucket = self.bucket0
        if key is None:
            key = self.key0
        self.c(["del", "s3://%s/%s" % (bucket, key)])

    def getBucketInfo(self, bucket = None):
        if bucket is None:
            bucket = self.bucket0
        return self.getThingInfo("s3://%s" % (bucket))

    def getObjectInfo(self, bucket = None, key = None):
        if bucket is None:
            bucket = self.bucket0
        if key is None:
            key = self.key0
        return self.getThingInfo("s3://%s/%s" % (bucket, key))

    def getThingInfo(self, thing):
        res = self.c(["info", thing])
        ll = str.splitlines(res.stdout)
        qq = [re.search(r"[:space:]*([^:]+):[:space:]*(.+)", l) for l in ll[1:]]
        qq = [[a.group(1).strip(), a.group(2).strip()] for a in qq]
        return qq

    def getBucketAcl(self, bucket = None):
        info = self.getBucketInfo(bucket = bucket)
        qq = dict([re.findall(r"[\w-]+", v) for (k,v) in info if k == "ACL"])
        return qq

    def getObjectAcl(self, bucket = None, key = None):
        info = self.getObjectInfo(bucket = bucket, key = key)
        qq = dict([re.findall(r"[\w-]+", v) for (k,v) in info if re.search("ACL", k)])
        return qq

    def setBucketAcl(self, bucket = None, acl_spec = {}):
        if bucket is None:
            bucket = self.bucket0
        if acl_spec == "public-read":
            acl_args = ["--acl-public"]
        else:
            acl_args = ["--acl-grant=%s:%s" % (g, p) for (g, p) in acl_spec]
        self.c(["setacl"] + acl_args + ["s3://%s" % (bucket)])

    def setObjectAcl(self, bucket = None, key = None, acl_spec = {}):
        if bucket is None:
            bucket = self.bucket0
        if key is None:
            key = self.key0
        if acl_spec == "public-read":
            acl_args = ["--acl-public"]
        else:
            acl_args = ["--acl-grant=%s:%s" % (g, p) for (g, p) in acl_spec]
        self.c(["setacl"] + acl_args + ["s3://%s/%s" % (bucket, key)])

    def getObjectStorageClass(self, bucket = None, key = None):
        info = self.getObjectInfo(bucket = bucket, key = key)
        return dict(info).get("Storage")

    def getBucketPolicy(self, bucket = None):
        info = self.getBucketInfo(bucket = bucket)
        return dict(info).get("Policy")

    def putBucketPolicy(self, bucket = None, policy = {}):
        if bucket is None:
            bucket = self.bucket0
        fn = "%s/bucketpolicy.json" % (self.scratch)
        with open(fn, "w+") as f:
            json.dump(policy, f)
        out = self.c(["setpolicy", fn, "s3://%s" % (bucket)])
        os.unlink(fn)

    def putObjectMetadata(self, bucket = None, key = None, metadata = {}):
        if bucket is None:
            bucket = self.bucket0
        if key is None:
            key = self.key0
        hh = ["--add-header=x-amz-meta-%s:%s" % (m, metadata[m]) for m in metadata]
        for h in hh:
            self.c(["modify", h, "s3://%s/%s" % (bucket, key)])

    def getObjectMetadata(self, bucket = None, key = None, metadata = []):
        if bucket is None:
            bucket = self.bucket0
        if key is None:
            key = self.key0
        info = self.getObjectInfo(bucket = bucket, key = key)
        return dict([x for x in info if re.search(r"x-amz-meta", x[0])])

    def copyObject(self, src_bucket, src_key, dst_bucket, dst_key):
        self.c(["cp", "s3://%s/%s" % (src_bucket, src_key), "s3://%s/%s" % (dst_bucket, dst_key)])

def create_user(host, port, name, email):
    os.environ['http_proxy'] = ''
    url = 'http://%s:%d/riak-cs/user' % (host, port)
    conn = httplib2.Http()
    resp, content = conn.request(url, "POST",
                                 headers = {"Content-Type": "application/json"},
                                 body = json.dumps({"email": email, "name": name}))
    conn.close()
    return json.loads(content)

def mineCoins(size = 1024):
    with open("/dev/urandom", 'rb') as f:
        return f.read(size)



class BasicTests(S3ApiVerificationTestBase):
    # def test_auth(self):
    #     bad_user = json.loads('{"email":"baduser@example.me","name":"baduser","name":"user1","key_id":"bad_key","key_secret":"BadSecret","id":"bad_canonical_id"}')
    #     bad_client = self.make_client(bad_user)
    #     self.assertRaises(botocore.exceptions.ClientError, bad_client.list_buckets)

    def test_create_bucket(self):
        self.createBucket()
        self.assertIn(self.bucket0, self.listBuckets())
        self.deleteBucket()

    def test_basic_crd(self, bucket = None, key = None, size = None, reuse_bucket = False):
        if key is None:
            key = self.key0
        if bucket is None:
            bucket = self.bucket0
        if size is None:
            size = 1024
            data = self.data0
        else:
            data = mineCoins(size)
        if not reuse_bucket:
            self.createBucket(bucket = bucket)

        self.putObject(bucket = bucket, key = key, value = data)
        self.assertIn(key, self.listKeys(bucket = bucket))
        self.assertEqual(data, self.getObject(bucket = bucket, key = key))
        info = dict(self.getObjectInfo(bucket = bucket, key = key))
        self.assertEqual(info.get("MD5 sum"),
                         str(hashlib.md5(data).hexdigest()))
        self.assertEqual(int(info.get("File size")),
                         len(data))
        self.deleteObject(bucket = bucket, key = key)
        self.assertNotIn(key, self.listKeys(bucket = bucket))
        with self.assertRaises(S3CmdException) as e:
            self.getObject(bucket = bucket, key = key)
        ee, = e.exception.args
        self.assertEqual(ee.returncode, 64)
        self.assertIn('does not exist', ee.stderr)
        if not reuse_bucket:
            self.deleteBucket(bucket = bucket)

    def test_japanese_key(self):
        self.test_basic_crd(key = u'日本語サフィックス')

    # def test_put_object_with_trailing_slash(self):
    # skipping because s3cmd doesn't recognize the url-quoted slash, nor unquotes the slash from %2F

    # def test_delete_objects(self):
    # skipping because s3cmd has no dedicated option to perform multiple deletions at a time

    def test_delete_bucket(self):
        self.createBucket()
        self.assertIn(self.bucket0, self.listBuckets())
        self.deleteBucket()
        self.assertNotIn(self.bucket0, self.listBuckets())

    def test_get_bucket_acl(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        res = self.getBucketAcl(bucket = bucket)
        self.assertEqual(res, {self.user1["name"]: 'FULL_CONTROL'})
        self.deleteBucket(bucket = bucket)

    def test_set_bucket_acl(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        self.setBucketAcl(bucket = bucket,
                          acl_spec = 'public-read')
        res = self.getBucketAcl(bucket = bucket)
        self.assertEqual(res, {self.user1["name"]: 'FULL_CONTROL',
                               "anon": 'READ'})
        self.deleteBucket(bucket = bucket)

    def test_get_object_acl(self):
        self.createBucket()
        self.putObject()
        res = self.getObjectAcl()
        self.assertEqual(res, {self.user1['name']: 'FULL_CONTROL'})
        self.deleteObject()
        self.deleteBucket()

    def test_set_object_acl(self):
        self.createBucket()
        self.putObject()
        self.setObjectAcl(acl_spec = 'public-read')
        res = self.getObjectAcl()
        self.assertEqual(res, {self.user1["name"]: 'FULL_CONTROL',
                               "anon": 'READ'})
        self.deleteObject()
        self.deleteBucket()

    def test_storage_class_standard(self):
        self.createBucket()
        self.putObject()
        res = self.getObjectStorageClass()
        self.assertEqual(res, 'STANDARD')
        self.deleteObject()
        self.deleteBucket()

    def test_storage_class_alt(self):
        self.createBucket()
        for storage_class in ['STANDARD', 'STANDARD_IA', 'ONEZONE_IA',
                              'INTELLIGENT_TIERING', 'GLACIER', 'DEEP_ARCHIVE']:
            key = str(uuid.uuid4())
            self.putObject(key = key,
                           extra_args = ["--storage-class=%s" % storage_class])
            self.assertEqual(storage_class, self.getObjectStorageClass(key = key))
            self.deleteObject(key = key)
        self.deleteBucket()

    def test_var_sizes(self):
        self.createBucket()
        self.test_basic_crd(reuse_bucket = True, size = 2 * 1024)
        self.test_basic_crd(reuse_bucket = True, size = 256 * 1024)
        self.test_basic_crd(reuse_bucket = True, size = 512 * 1024)
        self.test_basic_crd(reuse_bucket = True, size = 4 * 1024 * 1024)
        self.test_basic_crd(reuse_bucket = True, size = 8 * 1024 * 1024)   # sizes > 5M implicitly become multipart
        self.test_basic_crd(reuse_bucket = True, size = 32 * 1024 * 1024)
        self.deleteBucket()


class MultiPartUploadTests(S3ApiVerificationTestBase):
    # s3cmd has no dedicated InitiateMultiUpload call. Instead:
    # "Multipart uploads are automatically used when a file to upload is larger than 15MB"
    # and "minimum allowed chunk size is 5MB"
    def test_mp_basic(self, key = None, size = None):
        bucket = str(uuid.uuid4())
        if key is None:
            key = str(uuid.uuid4())
        if size is None:
            size = 16 * 1024 * 1024
        big_data = mineCoins(size)
        self.createBucket(bucket = bucket)
        self.putObject(bucket = bucket,
                       key = key,
                       value = big_data,
                       extra_args = ["--multipart-chunk-size-mb=5"])
        self.assertIn(key, self.listKeys(bucket = bucket))
        self.assertEqual(big_data, self.getObject(bucket = bucket, key = key))

        self.deleteObject(bucket = bucket, key = key)
        self.assertNotIn(key, self.listKeys(bucket = bucket))
        with self.assertRaises(S3CmdException) as e:
            self.getObject(bucket = bucket, key = key)
        ee, = e.exception.args
        self.assertEqual(ee.returncode, 64)
        self.assertIn('does not exist', ee.stderr)

        self.deleteObject(bucket = bucket, key = key)
        self.deleteBucket(bucket = bucket)

    def test_mp_300m(self):
        self.test_mp_basic(size = 300 * 1024 * 1024)

    def test_mp_acl(self):
        bucket = str(uuid.uuid4())
        key = str(uuid.uuid4())
        big_data = mineCoins(16 * 1024 * 1024)
        self.createBucket(bucket = bucket)
        self.putObject(bucket = bucket,
                       key = key,
                       value = big_data,
                       extra_args = ["--multipart-chunk-size-mb=5"])

        res = self.getObjectAcl(bucket = bucket, key = key)
        self.assertEqual(res, {self.user1['name']: 'FULL_CONTROL'})

        self.setObjectAcl(bucket = bucket,
                          key = key,
                          acl_spec = 'public-read')
        res = self.getObjectAcl(bucket = bucket, key = key)
        self.assertEqual(res, {self.user1["name"]: 'FULL_CONTROL',
                               "anon": 'READ'})

        self.deleteObject(bucket = bucket, key = key)
        self.deleteBucket(bucket = bucket)

    def test_mp_storage_class(self):
        bucket = str(uuid.uuid4())
        key = str(uuid.uuid4())
        big_data = mineCoins(16 * 1024 * 1024)
        self.createBucket(bucket = bucket)
        self.putObject(bucket = bucket,
                       key = key,
                       value = big_data,
                       extra_args = ["--multipart-chunk-size-mb=5"])
        res = self.getObjectStorageClass(bucket = bucket, key = key)
        self.assertEqual(res, 'STANDARD')
        self.deleteObject(bucket = bucket, key = key)
        self.deleteBucket(bucket = bucket)

    def test_mp_japanese_key(self):
        self.test_mp_basic(key = u'日本語サフィックス')


class BucketPolicyTest(S3ApiVerificationTestBase):
    "test bucket policy"

    def test_no_policy(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        self.assertEqual(self.getBucketPolicy(bucket = bucket), 'none')
        self.deleteBucket(bucket = bucket)

    def test_put_policy(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:GetObjectAcl","s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % bucket,
                    "Condition":{"IpAddress":{"aws:SourceIp":"127.0.0.1/32"}}
                 }
            ]
        }
        self.putBucketPolicy(bucket = bucket, policy = policy)
        got_policy = json.loads(self.getBucketPolicy(bucket = bucket))
        self.assertEqual(policy, got_policy)
        self.deleteBucket(bucket = bucket)

    def test_put_policy_correct_invalid_ip(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        faulty_policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:GetObjectAcl","s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % bucket,
                    "Condition":{"IpAddress":{"aws:SourceIp":"0"}}
                 }
            ]
        }
        with self.assertRaises(S3CmdException) as e:
            self.putBucketPolicy(bucket = bucket, policy = faulty_policy)
        ee, = e.exception.args
        self.assertEqual(ee.returncode, 11)
        self.assertEqual(ee.stderr, 'ERROR: S3 error: 400 (MalformedPolicy): Policy has invalid condition\n')
        self.assertEqual(self.getBucketPolicy(bucket = bucket), "none")
        self.deleteBucket(bucket = bucket)

    def test_put_policy_correct_version(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        policy = {
            "Version":"somebadversion",
            "Statement":[
                {
                    "Sid":"Stmtaaa",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:GetObjectAcl","s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % bucket,
                    "Condition":{"IpAddress":{"aws:SourceIp":"127.0.0.1/32"}}
                }
            ]
        }
        with self.assertRaises(S3CmdException) as e:
            self.putBucketPolicy(bucket = bucket, policy = policy)
        ee, = e.exception.args
        self.assertEqual(ee.returncode, 11)
        self.assertEqual(ee.stderr, 'ERROR: S3 error: 400 (MalformedPolicy): Document is invalid: Invalid Version somebadversion\n')
        self.assertEqual(self.getBucketPolicy(bucket = bucket), "none")
        self.deleteBucket(bucket = bucket)

    def test_ip_addr_policy(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa",
                    "Effect":"Deny",
                    "Principal":"*",
                    "Action":["s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % bucket,
                    "Condition":{"IpAddress":{"aws:SourceIp":"%s" % self.host}}
                }
            ]
        }
        self.putBucketPolicy(bucket = bucket, policy = policy)

        key = str(uuid.uuid4())
        self.putObject(bucket = bucket, key = key)
        with self.assertRaises(S3CmdException) as e:
            self.getObject(bucket = bucket, key = key)
        ee, = e.exception.args
        self.assertEqual(ee.returncode, 64)

        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % bucket,
                    "Condition":{"IpAddress":{"aws:SourceIp":"%s" % self.host}}
                }
            ]
        }
        self.putBucketPolicy(bucket = bucket, policy = policy)
        self.getObject(bucket = bucket, key = key) ## throws nothing
        self.deleteObject(bucket = bucket, key = key)
        self.deleteBucket(bucket = bucket)


    def test_invalid_transport_addr_policy(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)

        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa0",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % bucket,
                    "Condition":{"Bool":{"aws:SecureTransport":"wat"}}
                }
            ]
        }
        with self.assertRaises(S3CmdException) as e:
            self.putBucketPolicy(bucket = bucket, policy = policy)
        ee, = e.exception.args
        self.assertEqual(ee.returncode, 11)
        self.assertEqual(ee.stderr, 'ERROR: S3 error: 400 (MalformedPolicy): Policy has invalid condition\n')
        self.assertEqual(self.getBucketPolicy(bucket = bucket), "none")
        self.deleteBucket(bucket = bucket)

    def test_transport_addr_policy(self, size = 1024):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        key = str(uuid.uuid4())
        data = mineCoins(size)
        self.putObject(bucket = bucket, key = key, value = data)

        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa0",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:GetObject"],
                    "Resource":"arn:aws:s3:::%s/*" % bucket,
                    "Condition":{"Bool":{"aws:SecureTransport":False}}
                }
            ]
        }
        self.putBucketPolicy(bucket = bucket, policy = policy)
        self.assertEqual(self.getObject(bucket = bucket, key = key), data)

        ## policy accepts anyone who comes with http
        os.environ['http_proxy'] = ''
        conn = httplib2.Http()
        resp, content = conn.request('http://%s:%d/%s' % (self.host, self.port, key), "GET",
                                     headers = {"Host": "%s.s3.amazonaws.com" % bucket})
        conn.close()
        self.assertEqual(resp['status'], '200')
        self.assertEqual(content, self.getObject(bucket = bucket, key = key))

        ## anyone without https may not do any operation
        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa0",
                    "Effect":"Deny",
                    "Principal":"*",
                    "Action":"*",
                    "Resource":"arn:aws:s3:::%s/*" % bucket,
                    "Condition":{"Bool":{"aws:SecureTransport":False}}
                 }
            ]
        }
        self.putBucketPolicy(bucket = bucket, policy = policy)

        os.environ['http_proxy'] = ''
        conn = httplib2.Http()
        resp, content = conn.request('http://%s:%d/%s' % (self.host, self.port, key), "GET",
                                     headers = {"Host": "%s.s3.amazonaws.com" % bucket})
        conn.close()
        self.assertEqual(resp['status'], '403')

    def test_transport_addr_policy_multipart(self):
        self.test_transport_addr_policy(size = 16 * 1024 * 1024)

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

    def test_normal_object_metadata(self, size = 1024):
        key = str(uuid.uuid4())
        self.createBucket()
        self.putObject(key = key, value = mineCoins(size))
        self.putObjectMetadata(key = key, metadata = self.metadata)
        self.assert_metadata(key)
        self.putObjectMetadata(key = key, metadata = self.updated_metadata)
        self.assert_updated_metadata(key)

    def test_mp_object_metadata(self):
        self.test_normal_object_metadata(size = 16 * 1024 * 1024)

    def assert_metadata(self, key):
        md = self.getObjectMetadata(key = key)

        self.assertEqual(md['x-amz-meta-content-disposition'], self.metadata['Content-Disposition']),
        self.assertEqual(md['x-amz-meta-content-encoding'], self.metadata['Content-Encoding'])
        self.assertEqual(md['x-amz-meta-cache-control'], self.metadata['Cache-Control'])
        self.assertEqual(md['x-amz-meta-expires'], self.metadata['Expires'])
        self.assertEqual(md['x-amz-meta-mtime'], self.metadata["mtime"])
        self.assertEqual(md['x-amz-meta-uid'], self.metadata["UID"])
        self.assertEqual(md['x-amz-meta-with-hypen'], self.metadata["with-hypen"])
        self.assertEqual(md['x-amz-meta-space-in-value'], self.metadata["space-in-value"])
        # x-amz-meta-* headers should be normalized to lowercase
        self.assertEqual(md.get("Mtime"), None)
        self.assertEqual(md.get("MTIME"), None)
        self.assertEqual(md.get("Uid"), None)
        self.assertEqual(md.get("UID"), None)
        self.assertEqual(md.get("With-Hypen"), None)
        self.assertEqual(md.get("Space-In-Value"), None)

    def assert_updated_metadata(self, key):
        md = self.getObjectMetadata(key = key)

        expected_md = self.updated_metadata
        self.assertEqual(md['x-amz-meta-content-disposition'], self.updated_metadata['Content-Disposition']),
        self.assertEqual(md['x-amz-meta-cache-control'], self.updated_metadata['Cache-Control'])
        self.assertEqual(md['x-amz-meta-expires'], self.updated_metadata['Expires'])
        self.assertEqual(md['x-amz-meta-mtime'], self.updated_metadata["mtime"])
        self.assertEqual(md['x-amz-meta-uid'], self.updated_metadata["uid"])
        self.assertEqual(md['x-amz-meta-space-in-value'], self.updated_metadata["space-in-value"])
        self.assertEqual(md.get("Mtime"), None)
        self.assertEqual(md.get("MTIME"), None)
        self.assertEqual(md.get("Uid"), None)
        self.assertEqual(md.get("UID"), None)
        self.assertEqual(md.get("With-Hypen"), None)
        self.assertEqual(md.get("Space-In-Value"), None)


# class ContentMd5Test(S3ApiVerificationTestBase):
#     def test_catches_bad_md5(self):
# not applicable because s3cmd doesn't accept a md5 with put (to verify contents as boto does)

class SimpleCopyTest(S3ApiVerificationTestBase):

    def test_put_copy_object(self, size = 1024):
        self.createBucket()
        self.putObject(value = mineCoins(size))

        target_bucket = str(uuid.uuid4())
        target_key = str(uuid.uuid4())
        self.createBucket(target_bucket)

        self.copyObject(src_bucket = self.bucket0, src_key = self.key0,
                        dst_bucket = target_bucket, dst_key = target_key)

        self.assertEqual(self.getObject(bucket = self.bucket0, key = self.key0),
                         self.getObject(bucket = target_bucket, key = target_key))
        self.assertIn(target_key,
                      self.listKeys(bucket = target_bucket))

    def test_put_copy_object_from_mp(self):
        self.test_put_copy_object(size = 16 * 1024 * 1024)

    # def test_upload_part_from_non_mp(self):
    # no support for such fancy operations in s3cmd

    def test_put_copy_from_non_existing_key_404(self):
        self.createBucket()

        target_bucket = str(uuid.uuid4())
        target_key = str(uuid.uuid4())
        self.createBucket(target_bucket)

        with self.assertRaises(S3CmdException) as e:
            self.copyObject(src_bucket = self.bucket0, src_key = self.key0,
                            dst_bucket = target_bucket, dst_key = "ara")
        ee, = e.exception.args
        self.assertEqual(ee.returncode, 12)
        self.assertEqual(ee.stderr, 'WARNING: Key not found s3://%s/%s\n' % (self.bucket0, self.key0))

def mpp(blurb, thing):
    if os.environ.get('RCST_VERBOSE'):
        if int(os.environ.get('RCST_VERBOSE')) > 0:
            print("=========================")
            print(blurb)
            print("-------------------------")
            pprint.pp(thing)
            print

if __name__ == "__main__":
    unittest.main(verbosity=2)
