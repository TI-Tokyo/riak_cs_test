%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2014 Basho Technologies, Inc.  All Rights Reserved.
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

-module(upgrade_test).
-export([confirm/0]).
-include_lib("eunit/include/eunit.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").

-define(TEST_BUCKET, "riak-test-bucket-foobar").
-define(KEY_SINGLE_BLOCK,   "riak_test_key1").
-define(KEY_MULTIPLE_BLOCK, "riak_test_key2").

confirm() ->
    NumNodes = 1,
    %prepare_current(NumNodes),

    PrevConfig = rtcs_config:previous_configs(),
    {{UserConfig, _}, {RiakNodes, CSNodes}} =
        rtcs_dev:setup(NumNodes, PrevConfig, previous, #{with_policy => false}),

    {ok, Data} = prepare_all_data(UserConfig),
    ok = verify_all_data(UserConfig, Data),

    AdminCreds = {UserConfig#aws_config.access_key_id,
                  UserConfig#aws_config.secret_access_key},
    {_, RiakCurrentVsn} =
        rtcs_dev:riak_root_and_vsn(current),

    logger:info("Upgrading previous to current", []),
    rt:pmap(fun(N) -> rtcs_dev:stop(N, previous) end, CSNodes),
    rt:pmap(fun(N) -> rtcs_dev:stop(N, previous) end, RiakNodes),

    [begin
         N = rtcs_dev:node_id(RiakNode),
         ok = rt:upgrade(RiakNode, RiakCurrentVsn),
         ok = rtcs_config:upgrade_cs(N, AdminCreds),
         rtcs_dev:set_advanced_conf(
           {cs, current, N},
           [{riak_cs, [{riak_host, {"127.0.0.1", rtcs_config:pb_port(1)}}]}]
          )
     end || RiakNode <- RiakNodes],

    rt:pmap(fun(N) -> rtcs_dev:start(N, current) end, RiakNodes),
    ok = rt:wait_for_service(RiakNodes, riak_kv),
    ok = rt:wait_until_nodes_ready(RiakNodes),
    ok = rt:wait_until_no_pending_changes(RiakNodes),
    ok = rt:wait_until_ring_converged(RiakNodes),
    lists:map(fun(N) -> rtcs_dev:start(N, current),
                        ok = rt:wait_until_pingable(N) end, CSNodes),
    timer:sleep(2000),
    ok = verify_all_data(UserConfig, Data),
    ok = cleanup_all_data(UserConfig),
    logger:info("Upgrading to current successfully done"),

    pass.


%% prepare_current(NumNodes) ->
%%     logger:info("Preparing current cluster", []),
%%     {RiakNodes, CSNodes} =
%%         rtcs_dev:flavored_setup(#{num_nodes => NumNodes,
%%                                   flavor => rt_config:get(flavor, basic),
%%                                   config_spec => rtcs_config:configs([]),
%%                                   vsn => current}),
%%     rt:pmap(fun(N) -> rtcs_dev:stop(N, current) end, CSNodes),
%%     rt:pmap(fun(N) -> rtcs_dev:stop(N, current) end, RiakNodes),
%%     ok.


%% TODO: add more data and test cases
prepare_all_data(UserConfig) ->
    logger:info("User is valid on the cluster, and has no buckets"),
    ?assert(lists:member({buckets, []}, erlcloud_s3:list_buckets(UserConfig))),

    logger:info("creating bucket ~p", [?TEST_BUCKET]),
    ?assertEqual(ok, erlcloud_s3:create_bucket(?TEST_BUCKET, UserConfig)),

    [Bucket] = proplists:get_value(buckets, erlcloud_s3:list_buckets(UserConfig)),
    ?assert(lists:member({name, ?TEST_BUCKET}, Bucket)),

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
