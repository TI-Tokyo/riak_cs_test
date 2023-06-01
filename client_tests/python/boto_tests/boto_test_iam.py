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
<!-- The entity describing the SAMLtest IdP, named by the entityID below -->

<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="SAMLtestIdP" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:shibmd="urn:mace:shibboleth:metadata:1.0" xmlns:xml="http://www.w3.org/XML/1998/namespace" xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui" validUntil="2100-01-01T00:00:42Z" entityID="https://samltest.id/saml/idp">

    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:1.1:protocol urn:mace:shibboleth:1.0">

        <Extensions>
<!-- An enumeration of the domains this IdP is able to assert scoped attributes, which are
typically those with a @ delimiter, like mail.  Most IdP's serve only a single domain.  It's crucial
for the SP to check received attribute values match permitted domains to prevent a recognized IdP from
sending attribute values for which a different recognized IdP is authoritative. -->
            <shibmd:Scope regexp="false">samltest.id</shibmd:Scope>

<!-- Display information about this IdP that can be used by SP's and discovery
services to identify the IdP meaningfully for end users -->
            <mdui:UIInfo>
                <mdui:DisplayName xml:lang="en">SAMLtest IdP</mdui:DisplayName>
                <mdui:Description xml:lang="en">A free and basic IdP for testing SAML deployments</mdui:Description>
                <mdui:Logo height="90" width="225">https://samltest.id/saml/logo.png</mdui:Logo>
            </mdui:UIInfo>
        </Extensions>

        <KeyDescriptor use="signing">
            <ds:KeyInfo>
                    <ds:X509Data>
                        <ds:X509Certificate>
MIIDETCCAfmgAwIBAgIUZRpDhkNKl5eWtJqk0Bu1BgTTargwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLc2FtbHRlc3QuaWQwHhcNMTgwODI0MjExNDEwWhcNMzgw
ODI0MjExNDEwWjAWMRQwEgYDVQQDDAtzYW1sdGVzdC5pZDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAJrh9/PcDsiv3UeL8Iv9rf4WfLPxuOm9W6aCntEA
8l6c1LQ1Zyrz+Xa/40ZgP29ENf3oKKbPCzDcc6zooHMji2fBmgXp6Li3fQUzu7yd
+nIC2teejijVtrNLjn1WUTwmqjLtuzrKC/ePoZyIRjpoUxyEMJopAd4dJmAcCq/K
k2eYX9GYRlqvIjLFoGNgy2R4dWwAKwljyh6pdnPUgyO/WjRDrqUBRFrLQJorR2kD
c4seZUbmpZZfp4MjmWMDgyGM1ZnR0XvNLtYeWAyt0KkSvFoOMjZUeVK/4xR74F8e
8ToPqLmZEg9ZUx+4z2KjVK00LpdRkH9Uxhh03RQ0FabHW6UCAwEAAaNXMFUwHQYD
VR0OBBYEFJDbe6uSmYQScxpVJhmt7PsCG4IeMDQGA1UdEQQtMCuCC3NhbWx0ZXN0
LmlkhhxodHRwczovL3NhbWx0ZXN0LmlkL3NhbWwvaWRwMA0GCSqGSIb3DQEBCwUA
A4IBAQBNcF3zkw/g51q26uxgyuy4gQwnSr01Mhvix3Dj/Gak4tc4XwvxUdLQq+jC
cxr2Pie96klWhY/v/JiHDU2FJo9/VWxmc/YOk83whvNd7mWaNMUsX3xGv6AlZtCO
L3JhCpHjiN+kBcMgS5jrtGgV1Lz3/1zpGxykdvS0B4sPnFOcaCwHe2B9SOCWbDAN
JXpTjz1DmJO4ImyWPJpN1xsYKtm67Pefxmn0ax0uE2uuzq25h0xbTkqIQgJzyoE/
DPkBFK1vDkMfAW11dQ0BXatEnW7Gtkc0lh2/PIbHWj4AzxYMyBf5Gy6HSVOftwjC
voQR2qr2xJBixsg+MIORKtmKHLfU
                        </ds:X509Certificate>
                    </ds:X509Data>
            </ds:KeyInfo>

        </KeyDescriptor>
        <KeyDescriptor use="signing">
            <ds:KeyInfo>
                    <ds:X509Data>
                        <ds:X509Certificate>
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
                        </ds:X509Certificate>
                    </ds:X509Data>
            </ds:KeyInfo>

        </KeyDescriptor>
        <KeyDescriptor use="encryption">
            <ds:KeyInfo>
                    <ds:X509Data>
                        <ds:X509Certificate>
MIIDEjCCAfqgAwIBAgIVAPVbodo8Su7/BaHXUHykx0Pi5CFaMA0GCSqGSIb3DQEB
CwUAMBYxFDASBgNVBAMMC3NhbWx0ZXN0LmlkMB4XDTE4MDgyNDIxMTQwOVoXDTM4
MDgyNDIxMTQwOVowFjEUMBIGA1UEAwwLc2FtbHRlc3QuaWQwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCQb+1a7uDdTTBBFfwOUun3IQ9nEuKM98SmJDWa
MwM877elswKUTIBVh5gB2RIXAPZt7J/KGqypmgw9UNXFnoslpeZbA9fcAqqu28Z4
sSb2YSajV1ZgEYPUKvXwQEmLWN6aDhkn8HnEZNrmeXihTFdyr7wjsLj0JpQ+VUlc
4/J+hNuU7rGYZ1rKY8AA34qDVd4DiJ+DXW2PESfOu8lJSOteEaNtbmnvH8KlwkDs
1NvPTsI0W/m4SK0UdXo6LLaV8saIpJfnkVC/FwpBolBrRC/Em64UlBsRZm2T89ca
uzDee2yPUvbBd5kLErw+sC7i4xXa2rGmsQLYcBPhsRwnmBmlAgMBAAGjVzBVMB0G
A1UdDgQWBBRZ3exEu6rCwRe5C7f5QrPcAKRPUjA0BgNVHREELTArggtzYW1sdGVz
dC5pZIYcaHR0cHM6Ly9zYW1sdGVzdC5pZC9zYW1sL2lkcDANBgkqhkiG9w0BAQsF
AAOCAQEABZDFRNtcbvIRmblnZItoWCFhVUlq81ceSQddLYs8DqK340//hWNAbYdj
WcP85HhIZnrw6NGCO4bUipxZXhiqTA/A9d1BUll0vYB8qckYDEdPDduYCOYemKkD
dmnHMQWs9Y6zWiYuNKEJ9mf3+1N8knN/PK0TYVjVjXAf2CnOETDbLtlj6Nqb8La3
sQkYmU+aUdopbjd5JFFwbZRaj6KiHXHtnIRgu8sUXNPrgipUgZUOVhP0C0N5OfE4
JW8ZBrKgQC/6vJ2rSa9TlzI6JAa5Ww7gMXMP9M+cJUNQklcq+SBnTK8G+uBHgPKR
zBDsMIEzRtQZm4GIoHJae4zmnCekkQ==
                        </ds:X509Certificate>
                    </ds:X509Data>
            </ds:KeyInfo>

        </KeyDescriptor>

<!-- An endpoint for artifact resolution.  Please see Wikipedia for more details about SAML
     artifacts and when you may find them useful. -->

        <ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://samltest.id/idp/profile/SAML2/SOAP/ArtifactResolution" index="1" />

<!-- A set of endpoints where the IdP can receive logout messages. These must match the public
facing addresses if this IdP is hosted behind a reverse proxy.  -->
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://samltest.id/idp/profile/SAML2/Redirect/SLO"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://samltest.id/idp/profile/SAML2/POST/SLO"/>
        <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://samltest.id/idp/profile/SAML2/POST-SimpleSign/SLO"/>

<!-- A set of endpoints the SP can send AuthnRequests to in order to trigger user authentication. -->
        <SingleSignOnService Binding="urn:mace:shibboleth:1.0:profiles:AuthnRequest" Location="https://samltest.id/idp/profile/Shibboleth/SSO"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://samltest.id/idp/profile/SAML2/POST/SSO"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://samltest.id/idp/profile/SAML2/POST-SimpleSign/SSO"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://samltest.id/idp/profile/SAML2/Redirect/SSO"/>
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://samltest.id/idp/profile/SAML2/SOAP/ECP"/>

    </IDPSSODescriptor>

</EntityDescriptor>
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
  <saml:Issuer>https://samltest.id/saml/idp/metadata.php</saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
  <ds:Reference URI="#pfxba020796-590f-97ee-1d61-2fe77151ab31"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>kRWKZEafAZX6ZtWl0J+v073jxug=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>EFYcALAzoXEHlvMTPn2BkPAnIqYaQln1lwBUsZHBhv6bB4E7XuxsEZdj1ddFwkyEQSG8PQ1XwvnsxO9gsOS2MPve2Ih2DAY3RJalAxvt7FS5q6AEEKSgbKojfg8UHCenjd9i9/Uzdh7M5zzYdwidy1fy9TYixQD8bEL4m6JsID4=</ds:SignatureValue>
<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBSMQswCQYDVQQGEwJ1czETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMT25lbG9naW4gSW5jMRcwFQYDVQQDDA5zcC5leGFtcGxlLmNvbTAeFw0xNDA3MTcxNDEyNTZaFw0xNTA3MTcxNDEyNTZaMFIxCzAJBgNVBAYTAnVzMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxPbmVsb2dpbiBJbmMxFzAVBgNVBAMMDnNwLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZx+ON4IUoIWxgukTb1tOiX3bMYzYQiwWPUNMp+Fq82xoNogso2bykZG0yiJm5o8zv/sd6pGouayMgkx/2FSOdc36T0jGbCHuRSbtia0PEzNIRtmViMrt3AeoWBidRXmZsxCNLwgIV6dn2WpuE5Az0bHgpZnQxTKFek0BMKU/d8wIDAQABo1AwTjAdBgNVHQ4EFgQUGHxYqZYyX7cTxKVODVgZwSTdCnwwHwYDVR0jBBgwFoAUGHxYqZYyX7cTxKVODVgZwSTdCnwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQ0FAAOBgQByFOl+hMFICbd3DJfnp2Rgd/dqttsZG/tyhILWvErbio/DEe98mXpowhTkC04ENprOyXi7ZbUqiicF89uAGyt1oqgTUCD1VsLahqIcmrzgumNyTwLGWo17WDAa1/usDhetWAMhgzF/Cnf5ek0nK00m0YZGyc4LzgD0CROMASTWNg==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://samltest.id/saml/metadata.php</saml:Issuer>
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
      <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
        <saml:AttributeValue xsi:type="xs:string">NipToTheLoo</saml:AttributeValue>
      </saml:Attribute>
    <saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/SessionDuration">
      <saml:AttributeValue>1800</saml:AttributeValue>
    </saml:Attribute>
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
        print("create_role response:")
        pprint.pp(resp)

        boto3.set_stream_logger('')
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
