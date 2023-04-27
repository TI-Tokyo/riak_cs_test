#!/usr/bin/env python
# -*- coding: utf-8 -*-
## ---------------------------------------------------------------------
##
## Copyright (c) 2023 TI Tokyo    All Rights Reserved.
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

class RoleTest(AmzTestBase):
    "test CRUD on roles"

    def test_role_create(self):
        path = "/application_abc/component_xyz/"
        role_name = "VeryImportantRole"
        assume_role_policy_document = """
              {"Version":"2012-10-17","Statement":[{"Effect":"Allow",
               "Principal":{"Service":["ec2.amazonaws.com"]},"Action":["sts:AssumeRole"]}]}
        """
        description = "Unless required by applicable law"
        max_session_duration = 3600
        permissions_boundary = "arn:aws:iam::123456789012:role/application_abc/component_xyz/S3AccessRestrictions"
        tags = [
            {
                'Key': "Key1",
                'Value': "Value1"
            }
        ]
        #arn = "arn:aws:iam::123456789012:role/application_abc/component_xyz/S3Access"

        #boto3.set_stream_logger('')
        resp = self.iam_client.create_role(Path = path,
                                           RoleName = role_name,
                                           AssumeRolePolicyDocument = assume_role_policy_document,
                                           Description = description,
                                           MaxSessionDuration = max_session_duration,
                                           PermissionsBoundary = permissions_boundary,
                                           Tags = tags)
        self.assertEqual(resp['Role']['Path'], path)
        self.assertEqual(resp['Role']['RoleName'], role_name)
        self.assertEqual(resp['Role']['Description'], description)
