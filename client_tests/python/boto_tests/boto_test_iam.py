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

    def test_role_crud(self):
        resp = self.iam_client.create_role(**self.RoleSpecs)
        self.assertEqual(resp['Role']['Path'], self.RoleSpecs['Path'])
        self.assertEqual(resp['Role']['RoleName'], self.RoleSpecs['RoleName'])
        self.assertEqual(resp['Role']['Description'], self.RoleSpecs['Description'])
        self.assertEqual(resp['Role']['Tags'], self.RoleSpecs['Tags'])
        # print("CreateRole result:")
        # pprint.pp(resp)
        # print()

        #boto3.set_stream_logger('')
        resp = self.iam_client.get_role(RoleName = self.RoleSpecs['RoleName'])
        # print("GetRole result:")
        # pprint.pp(resp)
        # print()
        self.assertEqual(resp['Role']['Path'], self.RoleSpecs['Path'])
        self.assertEqual(resp['Role']['RoleName'], self.RoleSpecs['RoleName'])
        self.assertEqual(resp['Role']['Description'], self.RoleSpecs['Description'])

        resp = self.iam_client.list_roles(PathPrefix = "/")
        # print("ListRoles result:")
        # pprint.pp(resp)
        # print()
        self.assertEqual(len(resp['Roles']), 1)
        self.assertEqual(resp['Roles'][0]['RoleName'], self.RoleSpecs['RoleName'])

        resp = self.iam_client.delete_role(RoleName = self.RoleSpecs['RoleName'])
        # print("DeleteRole result:")
        # pprint.pp(resp)
        # print()

        resp = self.iam_client.list_roles(PathPrefix = "/")
        # print("After deletion, ListRoles result again:")
        # pprint.pp(resp)
        # print()
        self.assertEqual(len(resp['Roles']), 0)


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

    SAMLAssertion = """
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfxba020796-590f-97ee-1d61-2fe77151ab31" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfxba020796-590f-97ee-1d61-2fe77151ab31"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>kRWKZEafAZX6ZtWl0J+v073jxug=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>EFYcALAzoXEHlvMTPn2BkPAnIqYaQln1lwBUsZHBhv6bB4E7XuxsEZdj1ddFwkyEQSG8PQ1XwvnsxO9gsOS2MPve2Ih2DAY3RJalAxvt7FS5q6AEEKSgbKojfg8UHCenjd9i9/Uzdh7M5zzYdwidy1fy9TYixQD8bEL4m6JsID4=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
    <saml:Subject>
      <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
    """

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
        resp = self.iam_client.create_role(**self.RoleSpecs)
        self.role_arn = resp['Role']['Arn']

        boto3.set_stream_logger('')
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
