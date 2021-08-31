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

class BucketPolicyTest(S3ApiVerificationTestBase):
    "test bucket policy"

    def test_no_policy(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        self.client.delete_bucket_policy(Bucket = bucket)
        try:
            self.client.get_bucket_policy(Bucket = bucket)
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'NoSuchBucketPolicy')
        else:
            self.fail()
        self.deleteBucket(bucket = bucket)

    def create_bucket_and_set_policy(self, bucket, policy):
        self.createBucket(bucket = bucket)
        self.client.put_bucket_policy(Bucket = bucket,
                                      Policy = json.dumps(policy))

    def test_put_policy_invalid_ip(self):
        bucket = str(uuid.uuid4())
        policy = {
            "Version":"2020-10-17",
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
        try:
            self.create_bucket_and_set_policy(bucket, policy)
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'MalformedPolicy')
        self.deleteBucket(bucket = bucket)

    def test_put_policy(self):
        bucket = str(uuid.uuid4())
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
        self.create_bucket_and_set_policy(bucket, policy)
        got_policy = self.client.get_bucket_policy(Bucket = bucket)['Policy']
        self.assertEqual(policy, json.loads(got_policy))
        self.deleteBucket(bucket = bucket)

    def test_put_policy_2(self):
        bucket = str(uuid.uuid4())
        policy = {
            "Version":"2012-10-17",
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
        self.create_bucket_and_set_policy(bucket, policy)
        got_policy = self.client.get_bucket_policy(Bucket = bucket)['Policy']
        self.assertEqual(policy, json.loads(got_policy))
        self.deleteBucket(bucket = bucket)

    def test_put_policy_3(self):
        bucket = str(uuid.uuid4())
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
        try:
            self.create_bucket_and_set_policy(bucket, policy)
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'MalformedPolicy')
        self.deleteBucket(bucket = bucket)

    def test_ip_addr_policy(self):
        bucket = str(uuid.uuid4())
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
        self.create_bucket_and_set_policy(bucket, policy)

        self.putObject(bucket = bucket)
        try:
            self.getObject(bucket = bucket)
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
                    "Resource":"arn:aws:s3:::%s/*" % bucket,
                    "Condition":{"IpAddress":{"aws:SourceIp":"%s" % self.host}}
                }
            ]
        }
        self.client.put_bucket_policy(Bucket = bucket,
                                      Policy = json.dumps(policy))
        self.getObject(bucket = bucket) ## throws nothing
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
        try:
            self.client.put_bucket_policy(Bucket = bucket,
                                          Policy = json.dumps(policy))
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'MalformedPolicy')
        self.deleteBucket(bucket = bucket)

    def test_transport_addr_policy(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        self.putObject(bucket = bucket)

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
        self.client.put_bucket_policy(Bucket = bucket,
                                      Policy = json.dumps(policy))
        self.assertEqual(self.getObject(bucket = bucket), self.data)

        ## policy accepts anyone who comes with http
        os.environ['http_proxy'] = ''
        conn = httplib2.Http()
        resp, content = conn.request('http://%s:%d/%s' % (self.host, self.port, self.default_key), "GET",
                                     headers = {"Host": "%s.s3.amazonaws.com" % bucket})
        conn.close()
        self.assertEqual(resp['status'], '200')
        self.assertEqual(content, self.getObject(bucket = bucket))

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
        self.client.put_bucket_policy(Bucket = bucket,
                                      Policy = json.dumps(policy))

        os.environ['http_proxy'] = ''
        conn = httplib2.Http()
        resp, content = conn.request('http://%s:%d/%s' % (self.host, self.port, self.default_key), "GET",
                                     headers = {"Host": "%s.s3.amazonaws.com" % bucket})
        conn.close()
        self.assertEqual(resp['status'], '403')
        # abandon this bucket as we the policy we have set gets us an AccessDenied
        # self.deleteBucket(bucket = bucket)


class MultipartUploadTestsUnderPolicy(S3ApiVerificationTestBase):

    def test_small_strings_upload_1(self):
        bucket = str(uuid.uuid4())
        self.createBucket(bucket = bucket)
        parts = [b'this is part one', b'part two is just a rewording',
                 b'surprise that part three is pretty much the same',
                 b'and the last part is number four']
        expected_md5 = hashlib.md5(b''.join(parts)).hexdigest()

        key = str(uuid.uuid4())

        ## anyone may PUT this object
        policy = {
            "Version":"2008-10-17",
            "Statement":[
                {
                    "Sid":"Stmtaaa0",
                    "Effect":"Allow",
                    "Principal":"*",
                    "Action":["s3:PutObject"],
                    "Resource":"arn:aws:s3:::%s/*" % bucket,
                    "Condition":{"Bool":{"aws:SecureTransport":False}}
                 }
            ]}
        self.client.put_bucket_policy(Bucket = bucket,
                                      Policy = json.dumps(policy))
        upload_id, result = self.upload_multipart(bucket, key, parts)
        actual_md5 = hashlib.md5(bytes(self.getObject(bucket = bucket,
                                                      key = key))).hexdigest()
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
                    "Resource":"arn:aws:s3:::%s/*" % bucket,
                    "Condition":{"Bool":{"aws:SecureTransport":False}}
                }
            ]
        }
        self.client.put_bucket_policy(Bucket = bucket,
                                      Policy = json.dumps(policy))
        try:
            self.upload_multipart(bucket, key, parts)
            self.fail()
        except botocore.exceptions.ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'AccessDenied')
        self.deleteBucket(bucket = bucket)

