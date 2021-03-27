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

-compile(export_all).
-export([confirm/0]).

-include_lib("erlcloud/include/erlcloud_aws.hrl").
-include_lib("xmerl/include/xmerl.hrl").
-include_lib("eunit/include/eunit.hrl").

-include("riak_cs.hrl").

-define(BUCKET, "storage-stats-detailed").

-define(KEY1, "1").
-define(KEY2, "2").
-define(KEY3, "3").

confirm() ->
    rtcs:set_advanced_conf(cs, [{riak_cs, [{detailed_storage_calc, true}]}]),
    SetupRes = rtcs:setup(1),
    {AdminConfig, {RiakNodes, CSNodes, _Stanchion}} = SetupRes,
    RiakNode = hd(RiakNodes),
    UserConfig = rtcs_admin:create_user(RiakNode, 1),

    ?assertEqual(ok, erlcloud_s3:create_bucket(?BUCKET, UserConfig)),
    lager:info("Investigating stats for this empty bucket..."),
    assert_results_for_empty_bucket(AdminConfig, UserConfig, hd(CSNodes), ?BUCKET),

    setup_objects(UserConfig, ?BUCKET),
    lager:info("Investigating stats for non empty bucket..."),
    assert_results_for_non_empty_bucket(AdminConfig, UserConfig, hd(CSNodes), ?BUCKET),

    storage_stats_test:confirm_2(SetupRes),
    rtcs:pass().

assert_results_for_empty_bucket(AdminConfig, UserConfig, CSNode, Bucket) ->
    rt:setup_log_capture(CSNode),
    {Begin, End} = storage_stats_test:calc_storage_stats(CSNode),
    {JsonStat, XmlStat} = storage_stats_test:storage_stats_request(
                            AdminConfig, UserConfig, Begin, End),
    rtcs:reset_log(CSNode),
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
    Block1 = crypto:rand_bytes(100),
    ?assertEqual([{version_id, "null"}],
                 erlcloud_s3:put_object(Bucket, ?KEY1, Block1, UserConfig)),
    Block1Overwrite = crypto:rand_bytes(300),
    ?assertEqual([{version_id, "null"}],
                 erlcloud_s3:put_object(Bucket, ?KEY1, Block1Overwrite, UserConfig)),
    Block2 = crypto:rand_bytes(200),
    ?assertEqual([{version_id, "null"}],
                 erlcloud_s3:put_object(Bucket, ?KEY2, Block2, UserConfig)),
    ?assertEqual([{delete_marker, false}, {version_id, "null"}],
                 erlcloud_s3:delete_object(Bucket, ?KEY2, UserConfig)),

    InitRes = erlcloud_s3_multipart:initiate_upload(
                Bucket, ?KEY3, "text/plain", [], UserConfig),
    UploadId = erlcloud_xml:get_text(
                 "/InitiateMultipartUploadResult/UploadId", InitRes),
    MPBlocks = crypto:rand_bytes(2*1024*1024),
    {_RespHeaders1, _UploadRes} = erlcloud_s3_multipart:upload_part(
                                    Bucket, ?KEY3, UploadId, 1, MPBlocks, UserConfig),
    {_RespHeaders2, _UploadRes} = erlcloud_s3_multipart:upload_part(
                                    Bucket, ?KEY3, UploadId, 2, MPBlocks, UserConfig),
    ok.

assert_results_for_non_empty_bucket(AdminConfig, UserConfig, CSNode, Bucket) ->
    rt:setup_log_capture(CSNode),

    {Begin, End} = storage_stats_test:calc_storage_stats(CSNode),
    lager:info("Admin user will get every fields..."),
    {JsonStat, XmlStat} = storage_stats_test:storage_stats_request(
                            AdminConfig, UserConfig, Begin, End),

    ?assert(rtcs:json_get([<<"StartTime">>], JsonStat) =/= notfound),
    ?assert(rtcs:json_get([<<"EndTime">>],   JsonStat) =/= notfound),
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

    lager:info("Non-admin user will get only Objects and Bytes..."),
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
    lager:debug("assert json: ~p", [{K, V}]),
    ?assertEqual(V, rtcs:json_get([list_to_binary(Bucket), list_to_binary(K)],
                                  Sample)).

assert_storage_xml_stats(Bucket, K, V, Sample) ->
    lager:debug("assert xml: ~p", [{K, V}]),
    ?assertEqual(V, proplists:get_value(list_to_atom(K),
                                        proplists:get_value(Bucket, Sample),
                                        notfound)).
