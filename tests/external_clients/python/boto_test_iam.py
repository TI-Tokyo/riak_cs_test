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

class IAMTest(AmzTestBase):

    UserSpecs = {
        'UserName': "Johnny1273eecs3c2",
        'Tags': [
            {
                'Key': "Key1",
                'Value': "Value1"
            }
        ]
    }

    def test_users(self):
        resp = self.iam_client.create_user(**self.UserSpecs)
        mpp("CreateUser result:", resp)
        self.assertEqual(resp['User']['UserName'], self.UserSpecs['UserName'])
        self.assertEqual(resp['User']['Tags'], self.UserSpecs['Tags'])
        self.assertIn(self.UserSpecs['UserName'], resp['User']['Arn'])

        resp = self.iam_client.get_user(UserName = self.UserSpecs['UserName'])
        mpp("GetUser response", resp)
        self.assertEqual(resp['User']['UserName'], self.UserSpecs['UserName'])
        self.assertEqual(resp['User']['Tags'], self.UserSpecs['Tags'])
        self.assertIn(self.UserSpecs['UserName'], resp['User']['Arn'])

        resp = self.iam_client.list_users()
        mpp("ListUsers result:", resp)
        self.assertIn(self.UserSpecs['UserName'], [n['UserName'] for n in resp['Users']])

        resp = self.iam_client.delete_user(UserName = self.UserSpecs['UserName'])
        mpp("DeleteUser result:", resp)

        resp = self.iam_client.list_users()
        self.assertNotIn(self.UserSpecs['UserName'], [n['UserName'] for n in resp['Users']])

    RoleSpecs = {
        'Path': "/",
        'RoleName': "VeryImportantRole",
        'AssumeRolePolicyDocument': """
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "RoleForFunAndProfit",
            "Effect": "Allow",
            "Principal": "*",
            "Action": [ "iam:ListUsers" ],
            "Resource": "*"
        }
    ]
}
        """,
        'Description': "Unless required by applicable law",
        'MaxSessionDuration': 3600,
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

    def test_roles(self):
        resp = self.iam_client.create_role(**self.RoleSpecs)
        self.assertEqual(resp['Role']['Path'], self.RoleSpecs['Path'])
        self.assertEqual(resp['Role']['RoleName'], self.RoleSpecs['RoleName'])
        self.assertEqual(resp['Role']['Description'], self.RoleSpecs['Description'])
        self.assertEqual(resp['Role']['Tags'], self.RoleSpecs['Tags'])
        mpp("CreateRole result:", resp)

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

    PolicyDocument = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Principal": "*",
                "Effect": "Allow",
                "Action": "s3:ListAllMyBuckets",
                "Resource": "arn:aws:s3:::*"
            },
            {
                "Principal": "*",
                "Effect": "Allow",
                "Action": [
                    "s3:Get*",
                    "s3:List*"
                ],
                "Resource": "*"
            }
        ]
    }
    PolicySpecs = {
        'PolicyName': "PolicyOne",
        'Path': "/not/root",
        'PolicyDocument': json.dumps(PolicyDocument),
        'Description': "Fine print",
        'Tags': [
            {
                'Key': "stringkey",
                'Value': "stringvalue"
            }
        ]
    }

    def test_policies_crud(self):
        resp = self.iam_client.create_role(**self.RoleSpecs)

        resp = self.iam_client.create_policy(**self.PolicySpecs)
        p = resp['Policy']
        self.assertIn(self.PolicySpecs['PolicyName'], p['PolicyName'])
        self.assertEqual(p['CreateDate'].date(), datetime.date.today())
        self.assertEqual(p['Tags'], self.PolicySpecs['Tags'])
        arn = p['Arn']

        resp = self.iam_client.get_policy(PolicyArn = arn)
        mpp("GetPolicy: ", resp)

        resp = self.iam_client.list_policies()
        mpp('ListPolicies:', resp)
        self.assertIn(self.PolicySpecs['PolicyName'], [n['PolicyName'] for n in resp['Policies']])

        resp = self.iam_client.delete_policy(PolicyArn = arn)

        resp = self.iam_client.list_policies()
        self.assertNotIn(self.PolicySpecs['PolicyName'], [n['PolicyName'] for n in resp['Policies']])

        self.iam_client.delete_role(RoleName = self.RoleSpecs['RoleName'])

    def test_policies_attach(self):
        resp = self.iam_client.create_user(**self.UserSpecs)

        resp = self.iam_client.list_attached_user_policies(
            UserName = self.UserSpecs['UserName'])
        mpp("before attaching, ListAttachedUserPolicies:", resp)
        self.assertEqual(resp['AttachedPolicies'], [])

        resp = self.iam_client.create_policy(**self.PolicySpecs)
        policy_arn = resp['Policy']['Arn']

        res = self.iam_client.attach_user_policy(
            UserName = self.UserSpecs['UserName'],
            PolicyArn = policy_arn
        )

        resp = self.iam_client.list_attached_user_policies(
            UserName = self.UserSpecs['UserName'])
        mpp("after attaching ListAttachedUserPolicies:", resp)
        self.assertIn((policy_arn, self.PolicySpecs['PolicyName']),
                      [(n['PolicyArn'], n['PolicyName']) for n in resp['AttachedPolicies']])

        with self.assertRaises(Exception):
            self.iam_client.delete_user(UserName = self.UserSpecs['UserName'])

        resp = self.iam_client.detach_user_policy(
            UserName = self.UserSpecs['UserName'],
            PolicyArn = policy_arn
        )
        resp = self.iam_client.list_attached_user_policies(
            UserName = self.UserSpecs['UserName'])
        self.assertEqual(resp['AttachedPolicies'], [])

        self.iam_client.delete_policy(PolicyArn = policy_arn)
        self.iam_client.delete_user(UserName = self.UserSpecs['UserName'])


    IdPMetadata = from_file("idp_metadata.xml")
    SAMLProvider = {
        'Name': "CarpatDream",
        'SAMLMetadataDocument': IdPMetadata,
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

    def test_saml_providers(self):
        resp = self.iam_client.create_saml_provider(**self.SAMLProvider)
        self.assertIn(self.SAMLProvider['Name'], resp['SAMLProviderArn'])

        arn = resp['SAMLProviderArn']
        resp = self.iam_client.get_saml_provider(SAMLProviderArn = arn)

        self.assertEqual(resp['CreateDate'].date(), datetime.date.today())
        self.assertEqual(resp['Tags'], self.SAMLProvider['Tags'])

        resp = self.iam_client.list_saml_providers()
        mpp('ListSAMLProviders:', resp)
        self.assertEqual(len(resp['SAMLProviderList']), 1)

        resp = self.iam_client.delete_saml_provider(SAMLProviderArn = arn)

        resp = self.iam_client.list_saml_providers()
        mpp('ListSAMLProviders:', resp)
        self.assertEqual(len(resp['SAMLProviderList']), 0)


    def test_assume_role(self):
        resp = self.iam_client.create_role(**self.RoleSpecs)
        self.role_arn = resp['Role']['Arn']
        mpp("CreateRole response:", resp)

        resp = self.iam_client.list_roles(PathPrefix = "/")
        mpp("ListRoles response:", resp)

        resp = self.iam_client.create_saml_provider(**self.SAMLProvider)
        self.saml_provider_arn = resp['SAMLProviderArn']
        mpp("CreateSAMLProvider response:", resp)

        resp = self.iam_client.get_saml_provider(SAMLProviderArn = self.saml_provider_arn)
        mpp("GetSAMLProvider response:", resp)

        resp = self.sts_client.assume_role_with_saml(
            RoleArn = self.role_arn,
            PrincipalArn = self.saml_provider_arn,
            SAMLAssertion = str(base64.b64encode(bytes(self.SAMLAssertion, 'utf-8')))[2:-1],
            PolicyArns = [
                {
                    'arn': 'arn:aws:iam::123456789012:policy/ExtraPolicyThis',
                    'arn': 'arn:aws:iam::123456789013:policy/ExtraPolicyThat'
                },
            ],
            DurationSeconds = 1230)
        mpp("assume_role_with_saml response:", resp)
        assumed_role_user_key_id = resp['Credentials']['AccessKeyId']

        config = Config(signature_version = 's3v4')
        new_client = boto3.client('iam',
                                  use_ssl = False,
                                  aws_access_key_id = resp['Credentials']['AccessKeyId'],
                                  aws_secret_access_key = resp['Credentials']['SecretAccessKey'],
                                  config = config)
        resp = new_client.list_users()
        mpp("new_client.list_users response:", resp)
        self.assertIn("admin", [n['UserName'] for n in resp['Users']])
        self.assertIn("user2", [n['UserName'] for n in resp['Users']])

        mpp("Deleting role:", self.iam_client.delete_role(RoleName = self.RoleSpecs['RoleName']))
        mpp("Deleting SAML provider:", self.iam_client.delete_saml_provider(SAMLProviderArn = self.saml_provider_arn))

    def clean_up_iam_entities(self):
        resp = self.iam_client.list_saml_providers()
        for r in resp['SAMLProviderList']:
            self.iam_client.delete_saml_provider(SAMLProviderArn = r['Arn'])

        resp = self.iam_client.list_roles()
        for r in resp['Roles']:
            self.iam_client.delete_role(RoleName = r['RoleName'])

        resp = self.iam_client.list_policies()
        for r in resp['Policies']:
            self.iam_client.delete_policy(PolicyArn = r['Arn'])