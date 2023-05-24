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
    "test CRUD on roles"

    Role = {
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

    def test_role_crud(self):
        resp = self.iam_client.create_role(**self.Role)
        self.assertEqual(resp['Role']['Path'], self.Role['Path'])
        self.assertEqual(resp['Role']['RoleName'], self.Role['RoleName'])
        self.assertEqual(resp['Role']['Description'], self.Role['Description'])
        self.assertEqual(resp['Role']['Tags'], self.Role['Tags'])
        # print("CreateRole result:")
        # pprint.pp(resp)
        # print()

        #boto3.set_stream_logger('')
        resp = self.iam_client.get_role(RoleName = self.Role['RoleName'])
        # print("GetRole result:")
        # pprint.pp(resp)
        # print()
        self.assertEqual(resp['Role']['Path'], self.Role['Path'])
        self.assertEqual(resp['Role']['RoleName'], self.Role['RoleName'])
        self.assertEqual(resp['Role']['Description'], self.Role['Description'])

        resp = self.iam_client.list_roles(PathPrefix = "/")
        # print("ListRoles result:")
        # pprint.pp(resp)
        # print()
        self.assertEqual(len(resp['Roles']), 1)
        self.assertEqual(resp['Roles'][0]['RoleName'], self.Role['RoleName'])

        resp = self.iam_client.delete_role(RoleName = self.Role['RoleName'])
        # print("DeleteRole result:")
        # pprint.pp(resp)
        # print()

        resp = self.iam_client.list_roles(PathPrefix = "/")
        # print("After deletion, ListRoles result again:")
        # pprint.pp(resp)
        # print()
        self.assertEqual(len(resp['Roles']), 0)


class SAMLProviderTest(AmzTestBase):
    "SAML Provider ops"

    IdPMetadata = """
<MetadataProvider type="XML" validate="true"
    url="https://samltest.id/saml/idp"
    backingFilePath="SAMLtest.xml">
    <MetadataFilter type="RequireValidUntil" maxValidityInterval="2419200"/>
    <MetadataFilter type="Signature" certificate="signet.crt" verifyBackup="false"/>
    <Certificate>
    MIIDEjCCAfqgAwIBAgIVAMECQ1tjghafm5OxWDh9hwZfxthWMA0GCSqGSIb3DQEB
CwUAMBYxFDASBgNVBAMMC3NhbWx0ZXN0LmlkMB4XDTE4MDgyNDIxMTQwOVoXDTM4
MDgyNDIxMTQwOVowFjEUMBIGA1UEAwwLc2FtbHRlc3QuaWQwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQC0Z4QX1NFKs71ufbQwoQoW7qkNAJRIANGA4iM0
ThYghul3pC+FwrGv37aTxWXfA1UG9njKbbDreiDAZKngCgyjxj0uJ4lArgkr4AOE
jj5zXA81uGHARfUBctvQcsZpBIxDOvUUImAl+3NqLgMGF2fktxMG7kX3GEVNc1kl
bN3dfYsaw5dUrw25DheL9np7G/+28GwHPvLb4aptOiONbCaVvh9UMHEA9F7c0zfF
/cL5fOpdVa54wTI0u12CsFKt78h6lEGG5jUs/qX9clZncJM7EFkN3imPPy+0HC8n
spXiH/MZW8o2cqWRkrw3MzBZW3Ojk5nQj40V6NUbjb7kfejzAgMBAAGjVzBVMB0G
A1UdDgQWBBQT6Y9J3Tw/hOGc8PNV7JEE4k2ZNTA0BgNVHREELTArggtzYW1sdGVz
dC5pZIYcaHR0cHM6Ly9zYW1sdGVzdC5pZC9zYW1sL2lkcDANBgkqhkiG9w0BAQsF
AAOCAQEASk3guKfTkVhEaIVvxEPNR2w3vWt3fwmwJCccW98XXLWgNbu3YaMb2RSn
7Th4p3h+mfyk2don6au7Uyzc1Jd39RNv80TG5iQoxfCgphy1FYmmdaSfO8wvDtHT
TNiLArAxOYtzfYbzb5QrNNH/gQEN8RJaEf/g/1GTw9x/103dSMK0RXtl+fRs2nbl
D1JJKSQ3AdhxK/weP3aUPtLxVVJ9wMOQOfcy02l+hHMb6uAjsPOpOVKqi3M8XmcU
ZOpx4swtgGdeoSpeRyrtMvRwdcciNBp9UZome44qZAYH1iqrpmmjsfI9pJItsgWu
3kXPjhSfj1AJGR1l9JGvJrHki1iHTA==
    </Certificate>
</MetadataProvider>
    """
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
        resp = self.sts_client.assume_role_with_saml(
            RoleArn='arn:aws:iam::123456789012:role/TestSaml',
            PrincipalArn='arn:aws:iam::123456789012:saml-provider/SAML-test',
            SAMLAssertion="""VERYLONGENCODEDASSERTIONEXAMPLExzYW1sOkF1ZGllbmNl
PmJsYW5rPC9zYW1sOkF1ZGllbmNlPjwvc2FtbDpBdWRpZW5jZVJlc3RyaWN0aW9u
Pjwvc2FtbDpDb25kaXRpb25zPjxzYW1sOlN1YmplY3Q+PHNhbWw6TmFtZUlEIEZv
cm1hdD0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOm5hbWVpZC1mb3JtYXQ6
dHJhbnNpZW50Ij5TYW1sRXhhbXBsZTwvc2FtbDpOYW1lSUQ+PHNhbWw6U3ViamVj
dENvbmZpcm1hdGlvbiBNZXRob2Q9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIu
MDpjbTpiZWFyZXIiPjxzYW1sOlN1YmplY3RDb25maXJtYXRpb25EYXRhIE5vdE9u
T3JBZnRlcj0iMjAxOS0xMS0wMVQyMDoyNTowNS4xNDVaIiBSZWNpcGllbnQ9Imh0
dHBzOi8vc2lnbmluLmF3cy5hbWF6b24uY29tL3NhbWwiLz48L3NhbWw6U3ViamVj
dENvbmZpcm1hdGlvbj48L3NhbWw6U3ViamVjdD48c2FtbDpBdXRoblN0YXRlbWVu
dCBBdXRoPD94bWwgdmpSZXNwb25zZT4=""",
            PolicyArns=[
                {
                    'arn': 'arn:aws:iam::123456789012:policy/SpecificallyWhereItMatters'
                },
            ],
            Policy = 'arn:aws:iam::123456789012:policy/WhereItMattersGenerally',
            DurationSeconds = 1230)

        boto3.set_stream_logger('')
        config = Config()
        new_client = boto3.client('s3',
                                  use_ssl = False,
                                  aws_access_key_id = resp['Credentials']['AccessKeyId'],
                                  aws_secret_access_key = resp['Credentials']['SecretAccessKey'],
                                  config = config)
        resp = new_client.create_bucket(Bucket = "cando")
        pprint.pp(resp)
