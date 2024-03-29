%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2013 Basho Technologies, Inc.  All Rights Reserved.
%%               2021-2023 TI Tokyo    All Rights Reserved.
%%
%% This file is provided to you under the Apache License,
%% Version 2.0 (the "License"); you may not use this file
%% except in compliance with the License.  You may obtain
%% a copy of the License at
%%
%%   http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing,
%% software distributed under the License is distributed on an
%% "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
%% KIND, either express or implied.  See the License for the
%% specific language governing permissions and limitations
%% under the License.
%%
%% ---------------------------------------------------------------------

-module(buckets_test).

%% @doc `riak_test' module for testing object get behavior.

-export([confirm/0]).

-include("rtcs.hrl").

%% keys for non-multipart objects
-define(TEST_BUCKET,        "riak-test-bucket").
-define(KEY_SINGLE_BLOCK,   "riak_test_key1").
-define(REGION,             "boom-boom-tokyo-42").

%% keys for multipart uploaded objects
-define(KEY_MP,        "riak_test_mp").  % single part, single block
config() ->
    [{riak_cs, [{region, ?REGION}]}].

confirm() ->
    {{UserConfig, _}, {RiakNodes, CSNodes}} = rtcs_dev:setup(1, [{cs, config()}]),

    %% User 1, Cluster 1 config
    UserConfig1 = rtcs_admin:create_user(hd(RiakNodes), 1),

    ok = verify_create_delete(UserConfig),

    logger:info("creating bucket ~p", [?TEST_BUCKET]),
    ?assertEqual(ok, erlcloud_s3:create_bucket(?TEST_BUCKET, UserConfig)),

    ok = verify_bucket_location(UserConfig),

    ok = verify_bucket_delete_fails(UserConfig),

    ok = verify_bucket_mpcleanup(UserConfig),

    ok = verify_bucket_mpcleanup_racecond_and_fix(UserConfig, UserConfig1,
                                                  RiakNodes, hd(CSNodes)),

    ok = verify_cleanup_orphan_mp(UserConfig, UserConfig1, RiakNodes, hd(CSNodes)),

    ok = verify_max_buckets_per_user(UserConfig),

    pass.


verify_create_delete(UserConfig) ->
    logger:info("User is valid on the cluster, and has no buckets"),
    ?assertNoBuckets(UserConfig),
    logger:info("creating bucket ~p", [?TEST_BUCKET]),
    ?assertEqual(ok, erlcloud_s3:create_bucket(?TEST_BUCKET, UserConfig)),

    logger:info("deleting bucket ~p", [?TEST_BUCKET]),
    ?assertEqual(ok, erlcloud_s3:delete_bucket(?TEST_BUCKET, UserConfig)),
    logger:info("User is valid on the cluster, and has no buckets"),
    ?assertNoBuckets(UserConfig),
    ok.

verify_bucket_delete_fails(UserConfig) ->
    %% setup objects
    SingleBlock = crypto:strong_rand_bytes(400),
    erlcloud_s3:put_object(?TEST_BUCKET, ?KEY_SINGLE_BLOCK, SingleBlock, UserConfig),

    %% verify bucket deletion fails if any objects exist
    logger:info("deleting bucket ~p (to fail)", [?TEST_BUCKET]),
    ?assertError({aws_error, {http_error, _, _, _}},
                 erlcloud_s3:delete_bucket(?TEST_BUCKET, UserConfig)),

    %% cleanup object
    erlcloud_s3:delete_object(?TEST_BUCKET, ?KEY_SINGLE_BLOCK, UserConfig),
    ok.


verify_bucket_mpcleanup(UserConfig) ->
    Bucket = ?TEST_BUCKET,
    Key = ?KEY_SINGLE_BLOCK,
    {ok, InitUploadRes} = erlcloud_s3:start_multipart(Bucket, Key, [], [], UserConfig),
    UploadId = proplists:get_value(uploadId, InitUploadRes),

    %% make sure that mp uploads created
    {ok, UploadsList1} = erlcloud_s3:list_multipart_uploads(Bucket, [], [], UserConfig),
    Uploads1 = proplists:get_value(uploads, UploadsList1),
    lists:foreach(
      fun(UP) -> ?assertEqual(Key, proplists:get_value(key, UP)) end,
      Uploads1),
    ?assert(rtcs_multipart:upload_id_present(UploadId, Uploads1)),

    logger:info("deleting bucket ~p", [?TEST_BUCKET]),
    ?assertEqual(ok, erlcloud_s3:delete_bucket(?TEST_BUCKET, UserConfig)),

    %% check that writing mp uploads never resurrect
    %% after bucket delete
    ?assertEqual(ok, erlcloud_s3:create_bucket(?TEST_BUCKET, UserConfig)),
    {ok, UploadsList2} = erlcloud_s3:list_multipart_uploads(Bucket, [], [], UserConfig),
    Uploads2 = proplists:get_value(uploads, UploadsList2),
    ?assertEqual([], Uploads2),
    ok.

%% @doc in race condition: on delete_bucket
verify_bucket_mpcleanup_racecond_and_fix(UserConfig, UserConfig1,
                                         RiakNodes, CSNode) ->
    Key = ?KEY_MP,
    Bucket = ?TEST_BUCKET,
    prepare_bucket_with_orphan_mp(Bucket, Key, UserConfig, RiakNodes),

    %% then fail on creation
    %%TODO: check fail fail fail => 500
    ?assertHttpCode(409, erlcloud_s3:create_bucket(Bucket, UserConfig)),

    ?assertHttpCode(409, erlcloud_s3:create_bucket(Bucket, UserConfig1)),

    %% but we have a cleanup script, for existing system with 1.4.x or earlier
    %% DO cleanup here
    case rpc:call(CSNode, riak_cs_console, cleanup_orphan_multipart, []) of
        {badrpc, Error} ->
            logger:error("cleanup_orphan_multipart error: ~p", [Error]),
            throw(Error);
        Res ->
            logger:info("Result of cleanup_orphan_multipart: ~p", [Res])
    end,

    %% list_keys here? wait for GC?

    %% and Okay, it's clear, another user creates same bucket
    ?assertEqual(ok, erlcloud_s3:create_bucket(Bucket, UserConfig1)),

    %% Nothing found
    {ok, UploadsList2} = erlcloud_s3:list_multipart_uploads(Bucket, [], [], UserConfig1),
    Uploads2 = proplists:get_value(uploads, UploadsList2),
    ?assertEqual([], Uploads2),
    ok.

%% @doc cleanup orphan multipart for 30 buckets (> pool size)
verify_cleanup_orphan_mp(UserConfig, UserConfig1, RiakNodes, CSNode) ->
    [begin
         Suffix = integer_to_list(Index),
         Bucket = ?TEST_BUCKET ++ Suffix,
         Key = ?KEY_MP ++ Suffix,
         prepare_bucket_with_orphan_mp(Bucket, Key, UserConfig, RiakNodes)
     end || Index <- lists:seq(1, 30)],

    %% but we have a cleanup script, for existing system with 1.4.x or earlier
    %% DO cleanup here
    case rpc:call(CSNode, riak_cs_console, cleanup_orphan_multipart, []) of
        {badrpc, Error} ->
            logger:error("cleanup_orphan_multipart error: ~p", [Error]),
            throw(Error);
        Res ->
            logger:info("Result of cleanup_orphan_multipart: ~p", [Res])
    end,

    %% and Okay, it's clear, another user creates same bucket
    Bucket1 = ?TEST_BUCKET ++ "1",
    ?assertEqual(ok, erlcloud_s3:create_bucket(Bucket1, UserConfig1)),

    %% Nothing found
    {ok, UploadsList} = erlcloud_s3:list_multipart_uploads(Bucket1, [], [], UserConfig1),
    Uploads = proplists:get_value(uploads, UploadsList),
    ?assertEqual([], Uploads),
    ok.

prepare_bucket_with_orphan_mp(BucketName, Key, UserConfig, RiakNodes) ->
    ?assertEqual(ok, erlcloud_s3:create_bucket(BucketName, UserConfig)),
    {ok, _InitUploadRes} = erlcloud_s3:start_multipart(BucketName, Key, [], [], UserConfig),

    %% Reserve riak object to emulate prior 1.4.5 behavior afterwards
    {ok, ManiObj} = rc_helper:get_riakc_obj(RiakNodes, objects, BucketName, Key),

    ?assertEqual(ok, erlcloud_s3:delete_bucket(BucketName, UserConfig)),

    %% emulate a race condition, during the deletion MP initiate happened
    ok = rc_helper:update_riakc_obj(RiakNodes, objects, BucketName, Key, ManiObj).


verify_max_buckets_per_user(UserConfig) ->
    ListBucketsRes = erlcloud_s3:list_buckets(UserConfig),
    Buckets = proplists:get_value(buckets, ListBucketsRes),
    logger:debug("existing buckets: ~p", [Buckets]),
    BucketNameBase = "toomanybuckets",
    [begin
         BucketName = BucketNameBase++integer_to_list(N),
         logger:debug("creating bucket ~p", [BucketName]),
         ?assertEqual(ok,
                      erlcloud_s3:create_bucket(BucketName, UserConfig))
     end
     || N <- lists:seq(1,100-length(Buckets))],
    logger:info("100 buckets created", []),
    BucketName1 = BucketNameBase ++ "101",
    ?assertHttpCode(400, erlcloud_s3:create_bucket(BucketName1, UserConfig)),
    ok.

verify_bucket_location(UserConfig) ->
    ?assertEqual(?REGION,
                 erlcloud_s3:get_bucket_attribute(?TEST_BUCKET, location, UserConfig)).
