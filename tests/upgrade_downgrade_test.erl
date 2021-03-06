%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2014 Basho Technologies, Inc.  All Rights Reserved.
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

-module(upgrade_downgrade_test).
-export([confirm/0]).
-include_lib("eunit/include/eunit.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").

-define(TEST_BUCKET, "riak-test-bucket-foobar").
-define(KEY_SINGLE_BLOCK,   "riak_test_key1").
-define(KEY_MULTIPLE_BLOCK, "riak_test_key2").

confirm() ->
    NumNodes = 2,
    prepare_current(NumNodes),

    PrevConfig = rtcs_config:previous_configs(),
    {{UserConfig, _}, {RiakNodes, CSNodes, Stanchion} = Tussle} =
        rtcs:setup(NumNodes, PrevConfig, previous),

    {ok, Data} = prepare_all_data(UserConfig),
    ok = verify_all_data(UserConfig, Data),

    AdminCreds = {UserConfig#aws_config.access_key_id,
                  UserConfig#aws_config.secret_access_key},
    {_, RiakCurrentVsn} =
        rtcs_dev:riak_root_and_vsn(current),

    lager:info("Upgrading previous to current", []),
    rtcs_exec:stop_all_nodes(Tussle, previous),

    [begin
         N = rtcs_dev:node_id(RiakNode),
         ok = rt:upgrade(RiakNode, RiakCurrentVsn),
         ok = rtcs_config:upgrade_cs(N, AdminCreds),
         rtcs:set_advanced_conf({cs, current, N},
                                [{riak_cs,
                                  [{riak_host, {"127.0.0.1", rtcs_config:pb_port(1)}}]}])
     end || RiakNode <- RiakNodes],
    rtcs_config:migrate_stanchion(previous, current, AdminCreds),

    rtcs_exec:start_all_nodes(Tussle, current),

    ok = verify_all_data(UserConfig, Data),
    ok = cleanup_all_data(UserConfig),
    lager:info("Upgrading to current successfully done"),

    {ok, Data2} = prepare_all_data(UserConfig),

    {_, RiakPrevVsn} =
        rtcs_dev:riak_root_and_vsn(previous),


    lager:info("Downgrading current to previous", []),
    rtcs_exec:stop_all_nodes(Tussle, current),

    rtcs_config:migrate_stanchion(current, previous, AdminCreds),
    [begin
         N = rtcs_dev:node_id(RiakNode),
         ok = rt:upgrade(RiakNode, RiakPrevVsn),
         ok = rtcs_config:migrate_cs(current, previous, N, AdminCreds)
     end
     || RiakNode <- RiakNodes],

    rtcs_exec:start_all_nodes(Tussle, previous),

    ok = verify_all_data(UserConfig, Data2),
    lager:info("Downgrading to previous successfully done"),

    rtcs_dev:restore_configs(RiakNodes ++ CSNodes ++ [Stanchion], previous),
    rtcs_dev:pass().


prepare_current(NumNodes) ->
    lager:info("Preparing current cluster", []),
    {RiakNodes, CSNodes, _StanchionNode} = rtcs:flavored_setup(#{num_nodes => NumNodes,
                                                                 flavor => rt_config:get(flavor, basic),
                                                                 config_spec => rtcs_config:configs([]),
                                                                 vsn => current}),
    rt:pmap(fun(N) -> rtcs_exec:stop_cs(N, current) end, CSNodes),
    rtcs_exec:stop_stanchion(current),
    rt:pmap(fun(N) -> rtcs_dev:stop(N, current) end, RiakNodes),
    ok.


%% TODO: add more data and test cases
prepare_all_data(UserConfig) ->
    lager:info("User is valid on the cluster, and has no buckets"),
    ?assertEqual([{buckets, []}], erlcloud_s3:list_buckets(UserConfig)),

    lager:info("creating bucket ~p", [?TEST_BUCKET]),
    ?assertEqual(ok, erlcloud_s3:create_bucket(?TEST_BUCKET, UserConfig)),

    ?assertMatch([{buckets, [[{name, ?TEST_BUCKET}, _]]}],
                 erlcloud_s3:list_buckets(UserConfig)),

    %% setup objects
    SingleBlock = crypto:strong_rand_bytes(400),
    erlcloud_s3:put_object(?TEST_BUCKET, ?KEY_SINGLE_BLOCK, SingleBlock, UserConfig),
    MultipleBlock = crypto:strong_rand_bytes(4000000), % not aligned to block boundary
    erlcloud_s3:put_object(?TEST_BUCKET, ?KEY_MULTIPLE_BLOCK, MultipleBlock, UserConfig),

    {ok, [{single_block, SingleBlock},
          {multiple_block, MultipleBlock}]}.

%% TODO: add more data and test cases
verify_all_data(UserConfig, Data) ->
    SingleBlock = proplists:get_value(single_block, Data),
    MultipleBlock = proplists:get_value(multiple_block, Data),

    %% basic GET test cases
    basic_get_test_case(?TEST_BUCKET, ?KEY_SINGLE_BLOCK, SingleBlock, UserConfig),
    basic_get_test_case(?TEST_BUCKET, ?KEY_MULTIPLE_BLOCK, MultipleBlock, UserConfig),

    ok.

cleanup_all_data(UserConfig) ->
    erlcloud_s3:delete_object(?TEST_BUCKET, ?KEY_SINGLE_BLOCK, UserConfig),
    erlcloud_s3:delete_object(?TEST_BUCKET, ?KEY_MULTIPLE_BLOCK, UserConfig),
    erlcloud_s3:delete_bucket(?TEST_BUCKET, UserConfig),
    ok.

basic_get_test_case(Bucket, Key, ExpectedContent, Config) ->
    Obj = erlcloud_s3:get_object(Bucket, Key, Config),
    assert_whole_content(ExpectedContent, Obj).

assert_whole_content(ExpectedContent, ResultObj) ->
    Content = proplists:get_value(content, ResultObj),
    ContentLength = proplists:get_value(content_length, ResultObj),
    ?assertEqual(byte_size(ExpectedContent), list_to_integer(ContentLength)),
    ?assertEqual(byte_size(ExpectedContent), byte_size(Content)),
    ?assertEqual(ExpectedContent, Content).
