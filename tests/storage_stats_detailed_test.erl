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

-module(storage_stats_detailed_test).
%% @doc Integration test for storage statistics.

-export([confirm/0]).

-include("rtcs.hrl").
-include("riak_cs.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-define(BUCKET, "storage-stats-detailed").

-define(KEY1, "1").
-define(KEY2, "2").
-define(KEY3, "3").

confirm() ->
    ExtraConf = [{cs, [{riak_cs, [{detailed_storage_calc, true}]}]}],
    SetupRes = {{AdminConfig, _}, {[RiakNode|_], [CSNode|_]}} = rtcs_dev:setup(1, ExtraConf),

    rt:setup_log_capture(CSNode),

    UserConfig = rtcs_admin:create_user(RiakNode, 1),

    ?assertEqual(ok, erlcloud_s3:create_bucket(?BUCKET, UserConfig)),
    logger:info("Investigating stats for this empty bucket..."),
    assert_results_for_empty_bucket(AdminConfig, UserConfig, CSNode, ?BUCKET),

    setup_objects(UserConfig, ?BUCKET),
    logger:info("Investigating stats for non empty bucket..."),
    assert_results_for_non_empty_bucket(AdminConfig, UserConfig, CSNode, ?BUCKET),

    storage_stats_test:confirm_2(SetupRes),

    pass.

assert_results_for_empty_bucket(AdminConfig, UserConfig, CSNode, Bucket) ->
    {Begin, End} = storage_stats_test:calc_storage_stats(CSNode),
    {JsonStat, XmlStat} = storage_stats_test:storage_stats_request(
                            AdminConfig, UserConfig, Begin, End),
    rt:reset_log(CSNode),
    lists:foreach(fun(K) ->
                          assert_storage_json_stats(Bucket, K, 0, JsonStat),
                          assert_storage_xml_stats(Bucket, K, 0, XmlStat)
                  end,
                  ["Objects",
                   "Bytes",
                   "Blocks",
                   "WritingMultipartObjects",
                   "WritingMultipartBytes",
                   "WritingMultipartBlocks",
                   "ScheduledDeleteNewObjects",
                   "ScheduledDeleteNewBytes",
                   "ScheduledDeleteNewBlocks"]),
    ok.

setup_objects(UserConfig, Bucket) ->
    Block1 = crypto:strong_rand_bytes(100),
    ?assertProp(version_id, "null",
                erlcloud_s3:put_object(Bucket, ?KEY1, Block1, UserConfig)),
    Block1Overwrite = crypto:strong_rand_bytes(300),
    ?assertProp(version_id, "null",
                erlcloud_s3:put_object(Bucket, ?KEY1, Block1Overwrite, UserConfig)),
    Block2 = crypto:strong_rand_bytes(200),
    ?assertProp(version_id, "null",
                erlcloud_s3:put_object(Bucket, ?KEY2, Block2, UserConfig)),
    ?assertProp(version_id, "null",
                erlcloud_s3:delete_object(Bucket, ?KEY2, UserConfig)),

    {ok, InitRes} = erlcloud_s3:start_multipart(
                      Bucket, ?KEY3, [], [], UserConfig),
    UploadId = proplists:get_value(uploadId, InitRes),
    MPBlocks = crypto:strong_rand_bytes(2*1024*1024),
    {ok, _UploadRes1} = erlcloud_s3:upload_part(
                          Bucket, ?KEY3, UploadId, 1, MPBlocks, [], UserConfig),
    {ok, _UploadRes2} = erlcloud_s3:upload_part(
                          Bucket, ?KEY3, UploadId, 2, MPBlocks, [], UserConfig),
    ok.

assert_results_for_non_empty_bucket(AdminConfig, UserConfig, CSNode, Bucket) ->
    {Begin, End} = storage_stats_test:calc_storage_stats(CSNode),
    logger:info("Admin user will get every fields..."),
    {JsonStat, XmlStat} = storage_stats_test:storage_stats_request(
                            AdminConfig, UserConfig, Begin, End),

    ?assert(rtcs_dev:json_get([<<"StartTime">>], JsonStat) =/= notfound),
    ?assert(rtcs_dev:json_get([<<"EndTime">>],   JsonStat) =/= notfound),
    ?assert(proplists:get_value('StartTime', XmlStat)  =/= notfound),
    ?assert(proplists:get_value('EndTime',   XmlStat)  =/= notfound),
    lists:foreach(fun({K, V}) ->
                          assert_storage_json_stats(Bucket, K, V, JsonStat),
                          assert_storage_xml_stats(Bucket, K, V, XmlStat)
                  end,
                  [{"Objects",                   1 + 2},
                   {"Bytes",                     300 + 2 * 2*1024*1024},
                   {"Blocks",                    1 + 4},
                   {"WritingMultipartObjects",   2},
                   {"WritingMultipartBytes",     2 * 2*1024*1024},
                   {"WritingMultipartBlocks",    2 * 2},
                   {"ScheduledDeleteNewObjects", 2},
                   {"ScheduledDeleteNewBytes",   100 + 200},
                   {"ScheduledDeleteNewBlocks",  2}]),

    logger:info("Non-admin user will get only Objects and Bytes..."),
    {JsonStat2, XmlStat2} = storage_stats_test:storage_stats_request(
                              UserConfig, UserConfig, Begin, End),
    lists:foreach(fun({K, V}) ->
                          assert_storage_json_stats(Bucket, K, V, JsonStat2),
                          assert_storage_xml_stats(Bucket, K, V, XmlStat2)
                  end,
                  [{"Objects",                   1 + 2},
                   {"Bytes",                     300 + 2 * 2*1024*1024},
                   {"Blocks",                    notfound},
                   {"WritingMultipartObjects",   notfound},
                   {"WritingMultipartBytes",     notfound},
                   {"WritingMultipartBlocks",    notfound},
                   {"ScheduledDeleteNewObjects", notfound},
                   {"ScheduledDeleteNewBytes",   notfound},
                   {"ScheduledDeleteNewBlocks",  notfound}]),
    ok.

assert_storage_json_stats(Bucket, K, V, Sample) ->
    logger:debug("assert json: ~p", [{K, V}]),
    ?assertEqual(V, rtcs_dev:json_get(
                      [list_to_binary(Bucket), list_to_binary(K)],
                      Sample)).

assert_storage_xml_stats(Bucket, K, V, Sample) ->
    logger:debug("assert xml: ~p", [{K, V}]),
    ?assertEqual(V, proplists:get_value(list_to_atom(K),
                                        proplists:get_value(Bucket, Sample),
                                        notfound)).
