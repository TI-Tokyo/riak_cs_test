## ---------------------------------------------------------------------
##
## Copyright (c) 2007-2013 Basho Technologies, Inc.  All Rights Reserved.
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

require 'aws-sdk'
require 'uuid'
require 'yaml'
require 'helper'

class Aws::S3Control::Types::S3AccessControlList::Grant
  def  ==(other)
    @grantee.to_s == other.grantee.to_s and @permission.to_s == other.permission.to_s
  end
end

describe Aws::S3 do
  let(:s3) { Aws::S3::Client.new( s3_conf ) }
  let(:bucket_name) { "aws-sdk-test-" + UUID::generate }
  let(:object_name) { "key-" + UUID::generate }

  after :each do
    s3.list_buckets({}).buckets
      .each { |b| s3.list_objects({bucket: b.name}).contents
                .each { |o| s3.delete_object({bucket: b.name, key: o.key}) }
      s3.delete_bucket({bucket: b.name})
    }
  rescue Exception => e
  end

  describe "when there is no bucket" do
    it "should not find the bucket." do
      bb = s3.list_buckets({})
      bb.include?(bucket_name) == false
    end

    it "should fail on delete operation." do
      expect(lambda{s3.delete_bucket({bucket: bucket_name})})
        .to raise_error Aws::S3::Errors::NoSuchBucket
    end

    it "should fail on get acl operation" do
      expect(lambda{s3.get_bucket_acl({bucket: bucket_name})})
        .to raise_error Aws::S3::Errors::NoSuchBucket
    end
  end

  describe "when there is a bucket" do
    it "should be able to create and delete a bucket" do
      s3.create_bucket({bucket: bucket_name})
      bb = s3.list_buckets({})
      bb.include?(bucket_name) == true

      lambda{s3.delete_bucket({bucket: bucket_name}).should_not raise_error}
      s3.list_buckets({}).include?(bucket_name) == false
    end

    it "should be able to list buckets" do
      s3.create_bucket({bucket: bucket_name})
      expect(s3.list_buckets({}).buckets.any? { |b| b.name == bucket_name }).to be true
    end

    it "should be able to put, get and delete object" do
      expect(s3.create_bucket({bucket: bucket_name}).data)
        .to be_kind_of(Aws::S3::Types::CreateBucketOutput)

      expect(s3.put_object({bucket: bucket_name,
                            key: object_name,
                            body: 'Rakefile'}).data)
        .to be_kind_of(Aws::S3::Types::PutObjectOutput)
      expect(s3.get_object({bucket: bucket_name,
                            key: object_name}).body.read())
        .to eql('Rakefile')

      expect(s3.delete_object({bucket: bucket_name,
                               key: object_name}).data)
        .to be_kind_of(Aws::S3::Types::DeleteObjectOutput)
      expect(s3.list_objects({bucket: bucket_name}).contents)
        .to be_empty
    end

    it "should be able to put and get bucket ACL" do
      expect(s3.create_bucket({bucket: bucket_name, acl: "public-read"}).data)
        .to be_kind_of(Aws::S3::Types::CreateBucketOutput)
      expect(s3.get_bucket_acl({bucket: bucket_name}).data.grants[0].to_h)
        .to eql({:grantee=>{:type=>"Group",
                            :uri=>"http://acs.amazonaws.com/groups/global/AllUsers"},
                 :permission=>"READ"})
    end

    it "should be able to put and get object ACL" do
      expect(s3.create_bucket({bucket: bucket_name}).data)
        .to be_kind_of(Aws::S3::Types::CreateBucketOutput)
      expect(s3.put_object({bucket: bucket_name,
                            key: object_name,
                            acl: "public-read",
                            body: 'Rakefile'}).data)
        .to be_kind_of(Aws::S3::Types::PutObjectOutput)

      expect(s3.get_bucket_acl({bucket: bucket_name}).data.grants[0].to_h)
        .to eql({:grantee=>{:display_name=>"admin",
                            :id=>ENV['USER_ID'],
                            :type=>"CanonicalUser"},
                 :permission=>"FULL_CONTROL"})
    end

    it "should be able to put object using multipart upload" do
      s3.create_bucket({bucket: bucket_name})

      Tempfile.create('riakcs-test') do |f1|
        size = 1
        (size*1024/2).times {|i| f1.write "fa"}
        File.open(f1.path, 'rb') do |f2|
          s3.put_object({bucket: bucket_name,
                         key: object_name,
                         acl: "public-read",
                         body: f2})
        end
      end

      expect(s3.list_objects({bucket: bucket_name}).contents)
        .to satisfy {|a| a.any? { |o| o.key == object_name }
      }
    end
  end
end
