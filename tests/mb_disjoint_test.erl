%% Copyright (c) 2014 Basho Technologies, Inc.  All Rights Reserved.

-module(mb_disjoint_test).

%% @doc `riak_test' module for testing multi bag disjoint configuration

-export([confirm/0]).

-include("riak_cs.hrl").
-include("rtcs.hrl").

-define(TEST_BUCKET_CREATE_DELETE, "riak-test-bucket-create-delete").

-define(TEST_BUCKET,   "riak-test-bucket").
-define(KEY_NORMAL,    "key_normal").
-define(KEY_MULTIPART, "key_multipart").

confirm() ->
    NumNodes = 4,
    NodesOfMasterBag = 1,
    BagFlavor = disjoint,

    {RiakNodes, CSNodes} =
        rtcs_dev:setupNxMsingles(NodesOfMasterBag, NumNodes,
                             fun(_Nodes) -> rtcs_bag:set_conf(NodesOfMasterBag, BagFlavor) end,
                             current),
    UserConfig = rtcs_admin:create_user(hd(CSNodes), 1),
    rtcs_bag:set_weights(BagFlavor),

    logger:info("User is valid on the cluster, and has no buckets"),
    ?assertNoBuckets(UserConfig),

    assert_bucket_create_delete_twice(UserConfig),

    logger:info("creating bucket ~p", [?TEST_BUCKET]),
    ?assertEqual(ok, erlcloud_s3:create_bucket(?TEST_BUCKET, UserConfig)),

    ?assertHasBucket(?TEST_BUCKET, UserConfig),

    assert_object_in_expected_bag(RiakNodes, UserConfig, normal,
                                  ?TEST_BUCKET, ?KEY_NORMAL),
    assert_object_in_expected_bag(RiakNodes, UserConfig, multipart,
                                  ?TEST_BUCKET, ?KEY_MULTIPART),
    pass.


assert_bucket_create_delete_twice(UserConfig) ->
    ?assertEqual(ok, erlcloud_s3:create_bucket(?TEST_BUCKET_CREATE_DELETE, UserConfig)),
    ?assertEqual(ok, erlcloud_s3:delete_bucket(?TEST_BUCKET_CREATE_DELETE, UserConfig)),
    ?assertEqual(ok, erlcloud_s3:create_bucket(?TEST_BUCKET_CREATE_DELETE, UserConfig)),
    ?assertEqual(ok, erlcloud_s3:delete_bucket(?TEST_BUCKET_CREATE_DELETE, UserConfig)),
    ok.

assert_object_in_expected_bag(RiakNodes, UserConfig, UploadType, B, K) ->
    {Bucket, Key, Content} = rtcs_object:upload(UserConfig, UploadType, B, K),
    rtcs_object:assert_whole_content(UserConfig, Bucket, Key, Content),
    [_BagA, _BagB, BagC, BagD, BagE] = RiakNodes,

    %% riak-test-bucket goes to BagC, definitely
    ManifestBag = BagC,
    {_UUID, M} = rtcs_bag:assert_manifest_in_single_bag(
                   Bucket, Key, RiakNodes, ManifestBag),

    BlockBag = case rtcs_bag:high_low({Bucket, Key, M}) of
                   low  -> BagD;
                   high -> BagE
               end,
    ok = rtcs_bag:assert_block_in_single_bag(Bucket, M, RiakNodes, BlockBag),
    ok.
