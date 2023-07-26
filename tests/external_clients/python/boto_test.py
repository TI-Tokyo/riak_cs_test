#!/usr/bin/env python
## ---------------------------------------------------------------------
##
## Copyright (c) 2007-2013 Basho Technologies, Inc.  All Rights Reserved.
##               2021-2023 TI Tokyo    All Rights Reserved.
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

from boto_test_base import FileGenTest
from boto_test_basic import BasicTests, SimpleCopyTest, LargerFileUploadTest, UnicodeNamedObjectTest, ContentMd5Test
from boto_test_versioning import VersioningTests
from boto_test_multipart import MultiPartUploadTests, LargerMultipartFileUploadTest
from boto_test_policy import BucketPolicyTest, MultipartUploadTestsUnderPolicy
from boto_test_metadata import ObjectMetadataTest
from boto_test_iam import IAMTest
import unittest

if __name__ == "__main__":
    unittest.main(verbosity=2)
