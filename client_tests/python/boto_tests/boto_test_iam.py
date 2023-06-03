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
from botocore.client import Config
import json, uuid, base64, datetime
import pprint

class RoleTest(AmzTestBase):
    "CRUD on roles"

    RoleSpecs = {
        'Path': "/application_abc/component_xyz/",
        'RoleName': "VeryImportantRole",
        'AssumeRolePolicyDocument': """
{
    "Version": "2012-10-17",
    "Statement": {
        "Sid": "RoleForCognito",
        "Effect": "Allow",
        "Principal": {"Federated": "cognito-identity.amazonaws.com"},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {"StringEquals": {"cognito-identity.amazonaws.com:aud": "us-east:12345678-ffff-ffff-ffff-123456"}}
    }
}
        """,
        'Description': "Unless required by applicable law",
        'MaxSessionDuration': 3600,
        'PermissionsBoundary': "arn:aws:iam::123456789012:role/application_abc/component_xyz/S3AccessRestrictions",
        'Tags': [
            {
                'Key': "Key1",
                'Value': "Value1"
            },
            {
                'Key': "Key2",
                'Value': "OOOOOOOOOOOOOOOOOO"
            }
        ]
    }
    role_arn = None
    saml_provider_arn = None

    def test_role_crud(self):
        mpl()
        resp = self.iam_client.create_role(**self.RoleSpecs)
        self.assertEqual(resp['Role']['Path'], self.RoleSpecs['Path'])
        self.assertEqual(resp['Role']['RoleName'], self.RoleSpecs['RoleName'])
        self.assertEqual(resp['Role']['Description'], self.RoleSpecs['Description'])
        self.assertEqual(resp['Role']['Tags'], self.RoleSpecs['Tags'])
        mpp("CreateRole result:", resp)

        boto3.set_stream_logger('')
        resp = self.iam_client.get_role(RoleName = self.RoleSpecs['RoleName'])
        mpp("GetRole result:", resp)

        self.assertEqual(resp['Role']['Path'], self.RoleSpecs['Path'])
        self.assertEqual(resp['Role']['RoleName'], self.RoleSpecs['RoleName'])
        self.assertEqual(resp['Role']['Description'], self.RoleSpecs['Description'])

        resp = self.iam_client.list_roles(PathPrefix = "/")
        mpp("ListRoles result:", resp)
        self.assertEqual(len(resp['Roles']), 1)
        self.assertEqual(resp['Roles'][0]['RoleName'], self.RoleSpecs['RoleName'])

        resp = self.iam_client.delete_role(RoleName = self.RoleSpecs['RoleName'])
        mpp("DeleteRole result:", resp)

        resp = self.iam_client.list_roles(PathPrefix = "/")
        mpp("After deletion, ListRoles result again:", resp)
        self.assertEqual(len(resp['Roles']), 0)


    IdPMetadata = from_file("idp_metadata.xml")
    SAMLProvider = {
        'Name': "CarpatDream",
        'SAMLMetadataDocument': str(base64.b64encode(bytes(IdPMetadata, 'utf-8')))[2:-1],
        'Tags': [
            {
                'Key': "Key1",
                'Value': "Value1"
            },
            {
                'Key': "Key2",
                'Value': "Value3"
            }
        ]
    }

    SAMLAssertion = from_file("saml_assertion.xml")

    def test_saml_provider(self):
        resp = self.iam_client.create_saml_provider(**self.SAMLProvider)
        self.assertIn(self.SAMLProvider['Name'], resp['SAMLProviderArn'])

        arn = resp['SAMLProviderArn']
        resp = self.iam_client.get_saml_provider(SAMLProviderArn = arn)

        self.assertEqual(resp['CreateDate'].date(), datetime.date.today())
        self.assertEqual(resp['Tags'], self.SAMLProvider['Tags'])

        resp = self.iam_client.list_saml_providers()

        resp = self.iam_client.delete_saml_provider(SAMLProviderArn = arn)

    def test_assume_role(self):
        mpl()
        resp = self.iam_client.create_role(**self.RoleSpecs)
        self.role_arn = resp['Role']['Arn']
        print("create_role response:")
        pprint.pp(resp)

        resp = self.iam_client.create_saml_provider(**self.SAMLProvider)
        self.saml_provider_arn = resp['SAMLProviderArn']
        print("create_saml_provider response:")
        pprint.pp(resp)

        resp = self.iam_client.get_saml_provider(SAMLProviderArn = self.saml_provider_arn)
        print("get_saml_provider response:")
        pprint.pp(resp)

        resp = self.sts_client.assume_role_with_saml(
            RoleArn = self.role_arn,
            PrincipalArn='arn:aws:iam::123456789012:saml-provider/SAML-test',
            SAMLAssertion = str(base64.b64encode(bytes(self.SAMLAssertion, 'utf-8')))[2:-1],
            PolicyArns=[
                {
                    'arn': 'arn:aws:iam::123456789012:policy/SpecificallyWhereItMatters'
                },
            ],
            Policy = 'arn:aws:iam::123456789012:policy/WhereItMattersGenerally',
            DurationSeconds = 1230)
        pprint.pp(resp)

        config = Config()
        new_client = boto3.client('s3',
                                  use_ssl = False,
                                  aws_access_key_id = resp['Credentials']['AccessKeyId'],
                                  aws_secret_access_key = resp['Credentials']['SecretAccessKey'],
                                  config = config)
        resp = new_client.list_buckets()
        pprint.pp(resp)

        self.iam_client.delete_role(RoleName = self.RoleSpecs['RoleName'])
        self.iam_client.delete_saml_provider(SAMLProviderArn = self.saml_provider_arn)

