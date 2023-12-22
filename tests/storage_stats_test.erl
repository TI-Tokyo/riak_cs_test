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

-module(storage_stats_test).
%% @doc Integration test for storage statistics.

-export([confirm/0, confirm_1/1, confirm_2/1,
         calc_storage_stats/1,
         storage_stats_request/3,
         storage_stats_request/4]).

-include("rtcs.hrl").
-include("riak_cs.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-define(BUCKET1, "storage-stats-test-1").
-define(BUCKET2, "storage-stats-test-2").
-define(BUCKET3, "storage-stats-test-3").

-define(BUCKET4, "storage-stats-test-4").
-define(BUCKET5, "storage-stats-test-5").
-define(BUCKET6, "storage-stats-test-6").
-define(BUCKET7, "storage-stats-test-7").
-define(BUCKET8, "storage-stats-test-8").

-define(BUCKET9, "storage-stats-test-9").

-define(KEY, "1").

-define(HIDDEN_KEY, "5=pockets").

confirm() ->
    confirm_1(false).

confirm_1(Use2iForStorageCalc) when is_boolean(Use2iForStorageCalc) ->
    Conf = [{riak, [{riak_kv, [{delete_mode, keep}]}]},
            {cs, [{riak_cs,
                   [{use_2i_for_storage_calc, Use2iForStorageCalc}]}]}],
    confirm_2(
      rtcs_dev:setup(1, Conf)).

confirm_2({{UserConfig, _}, {[RiakNode], [CSNode]}}) ->
    UserConfig2 = rtcs_admin:create_user(CSNode, 2),

    TestSpecs = [store_object(?BUCKET1, UserConfig),
                 delete_object(?BUCKET2, UserConfig),
                 store_objects(?BUCKET3, UserConfig),

                 %% for CS #840 regression
                 store_object(?BUCKET4, UserConfig),
                 store_object(?BUCKET5, UserConfig),
                 store_object(?BUCKET6, UserConfig),
                 store_object(?BUCKET7, UserConfig),
                 store_object(?BUCKET8, UserConfig),
                 give_over_bucket(?BUCKET9, UserConfig, UserConfig2)
                ],

    verify_cs840_regression(UserConfig, [RiakNode]),

    %% Set up to grep logs to verify messages
    rt:setup_log_capture(CSNode),

    {Begin, End} = calc_storage_stats(CSNode),
    logger:info("going to issue stats requests as user ~p", [UserConfig#aws_config.access_key_id]),
    {JsonStat, XmlStat} = storage_stats_request(UserConfig, Begin, End),
    lists:foreach(fun(Spec) ->
                          assert_storage_json_stats(Spec, JsonStat),
                          assert_storage_xml_stats(Spec, XmlStat)
                  end, TestSpecs),

    pass.


%% @doc garbage data to check #840 regression,
%% due to this garbages, following tests may fail
%% makes manifest in BUCKET(4,5,6,7,8) to garbage, which can
%% be generated from former versions of riak cs than 1.4.5
verify_cs840_regression(UserConfig, RiakNodes) ->

    %% None of thes objects should not be calculated effective in storage
    ok = mess_with_writing_various_props(
           RiakNodes, UserConfig,
           [%% state=writing, .props=undefined
            {?BUCKET4, ?KEY, writing, undefined},
            %% badly created ongoing multipart uploads (not really)
            {?BUCKET5, ?KEY, writing, [{multipart, undefined}]},
            {?BUCKET6, ?KEY, writing, [{multipart, pocketburgerking}]}]),

    %% state=active, .props=undefined in {?BUCKET7, ?KEY}
    ok = mess_with_active_undefined(RiakNodes),
    %% tombstone in siblings in {?BUCKET8, ?KEY}
    ok = mess_with_tombstone(RiakNodes, UserConfig),
    ok.

mess_with_writing_various_props(RiakNodes, UserConfig, VariousProps) ->
    F = fun({CSBucket, CSKey, NewState, Props}) ->
                Bucket = <<"0o:", (crypto:hash(md5, list_to_binary(CSBucket)))/binary>>,
                Pid = rtcs_dev:pbc(RiakNodes, objects, CSBucket),
                {ok, RiakObject0} = riakc_pb_socket:get(Pid, Bucket, list_to_binary(CSKey)),
                [{UUID, Manifest0}|_] = hd([binary_to_term(V) || V <- riakc_obj:get_values(RiakObject0)]),
                Manifest1 = Manifest0?MANIFEST{state=NewState, props=Props},
                RiakObject = riakc_obj:update_value(RiakObject0,
                                                    term_to_binary([{UUID, Manifest1}])),
                logger:debug("~p", [Manifest1?MANIFEST.props]),

                Block = crypto:strong_rand_bytes(100),
                ?assertProp(version_id, "null",
                            erlcloud_s3:put_object(CSBucket, CSKey, Block, UserConfig)),
                ok = riakc_pb_socket:put(Pid, RiakObject),
                assure_num_siblings(Pid, Bucket, list_to_binary(CSKey), 2),
                ok = riakc_pb_socket:stop(Pid)
        end,
    lists:foreach(F, VariousProps).


mess_with_active_undefined(RiakNodes) ->
    CSBucket = ?BUCKET7, CSKey = ?KEY,
    Pid = rtcs_dev:pbc(RiakNodes, objects, CSBucket),
    Bucket = <<"0o:", (crypto:hash(md5, list_to_binary(CSBucket)))/binary>>,
    {ok, RiakObject0} = riakc_pb_socket:get(Pid, Bucket, list_to_binary(CSKey)),
    [{UUID, Manifest0}|_] = hd([binary_to_term(V) || V <- riakc_obj:get_values(RiakObject0)]),
    Manifest1 = Manifest0?MANIFEST{props=undefined},
    RiakObject = riakc_obj:update_value(RiakObject0,
                                        term_to_binary([{UUID, Manifest1}])),
    ok = riakc_pb_socket:put(Pid, RiakObject),
    ok = riakc_pb_socket:stop(Pid).

%% @doc messing with tombstone (see above adding {delete_mode, keep} to riak_kv)
mess_with_tombstone(RiakNodes, UserConfig) ->
    CSBucket = ?BUCKET8,
    CSKey = ?KEY,
    Pid = rtcs_dev:pbc(RiakNodes, objects, CSBucket),
    Block = crypto:strong_rand_bytes(100),
    ?assertProp(version_id, "null", erlcloud_s3:put_object(CSBucket, CSKey, Block, UserConfig)),
    Bucket = <<"0o:", (crypto:hash(md5, list_to_binary(?BUCKET8)))/binary>>,

    %% %% This leaves a tombstone which messes up the storage calc
    ok = riakc_pb_socket:delete(Pid, Bucket, list_to_binary(CSKey)),
    %% logger:info("listkeys: ~p", [riakc_pb_socket:list_keys(Pid, Bucket)]),

    ?assertProp(version_id, "null", erlcloud_s3:put_object(?BUCKET8, CSKey, Block, UserConfig)),

    {ok, RiakObject0} = riakc_pb_socket:get(Pid, Bucket, list_to_binary(CSKey)),
    assure_num_siblings(Pid, Bucket, list_to_binary(CSKey), 1),

    Block2 = crypto:strong_rand_bytes(100),
    ?assertProp(version_id, "null", erlcloud_s3:put_object(?BUCKET8, CSKey, Block2, UserConfig)),

    ok = riakc_pb_socket:delete_vclock(Pid, Bucket, list_to_binary(CSKey),
                                       riakc_obj:vclock(RiakObject0)),

    %% Two siblings, alive object and new tombstone
    assure_num_siblings(Pid, Bucket, list_to_binary(CSKey), 2),

    %% Here at last, ?BUCKET8 should have ?KEY alive and counted, but
    %% #840 causes, ?KEY won't be counted in usage calc
    Obj = erlcloud_s3:get_object(?BUCKET8, CSKey, UserConfig),
    ?assertEqual(byte_size(Block2), list_to_integer(proplists:get_value(content_length, Obj))),
    ?assertEqual(Block2, proplists:get_value(content, Obj)),
    ok = riakc_pb_socket:stop(Pid).

assure_num_siblings(Pid, Bucket, Key, Num) ->
    {ok, RiakObject0} = riakc_pb_socket:get(Pid, Bucket, Key),
    Contents = riakc_obj:get_values(RiakObject0),
    ?assertEqual(Num, length(Contents)).


store_object(Bucket, UserConfig) ->
    logger:info("creating bucket ~p", [Bucket]),
    %% Create bucket
    ?assertEqual(ok, erlcloud_s3:create_bucket(Bucket, UserConfig)),
    %% Put 100-byte object
    Block = crypto:strong_rand_bytes(100),
    ?assertProp(version_id, "null", erlcloud_s3:put_object(Bucket, ?KEY, Block, UserConfig)),
    ExpectedObjects = 1,
    ExpectedBytes = 100,
    {Bucket, ExpectedObjects, ExpectedBytes}.

delete_object(Bucket, UserConfig) ->
    logger:info("creating bucket ~p", [Bucket]),
    %% Create bucket
    ?assertEqual(ok, erlcloud_s3:create_bucket(Bucket, UserConfig)),
    %% Put 100-byte object
    Block = crypto:strong_rand_bytes(100),
    ?assertProp(version_id, "null", erlcloud_s3:put_object(Bucket, ?KEY, Block, UserConfig)),
    ?assertProp(version_id, "null", erlcloud_s3:delete_object(Bucket, ?KEY, UserConfig)),
    ExpectedObjects = 0,
    ExpectedBytes = 0,
    {Bucket, ExpectedObjects, ExpectedBytes}.

store_objects(Bucket, UserConfig) ->
    logger:info("creating bucket ~p", [Bucket]),
    %% Create bucket
    ?assertEqual(ok, erlcloud_s3:create_bucket(Bucket, UserConfig)),
    %% Put 100-byte object 10 times
    Block = crypto:strong_rand_bytes(100),
    [?assertProp(version_id, "null",
                 erlcloud_s3:put_object(Bucket, integer_to_list(Key), Block, UserConfig))
     || Key <- lists:seq(1, 10)],
    ExpectedObjects = 10,
    ExpectedBytes = 1000,
    {Bucket, ExpectedObjects, ExpectedBytes}.

give_over_bucket(Bucket, UserConfig, AnotherUser) ->
    %% Create bucket, put/delete object, delete bucket finally
    ?assertEqual(ok, erlcloud_s3:create_bucket(Bucket, UserConfig)),
    Block = crypto:strong_rand_bytes(100),
    ?assertProp(version_id, "null", erlcloud_s3:put_object(Bucket, ?KEY, Block, UserConfig)),
    ?assertProp(version_id, "null", erlcloud_s3:delete_object(Bucket, ?KEY, UserConfig)),
    ?assertEqual(ok, erlcloud_s3:delete_bucket(Bucket, UserConfig)),

    %% Another user re-create the bucket and put an object into it.
    ?assertEqual(ok, erlcloud_s3:create_bucket(Bucket, AnotherUser)),
    Block2 = crypto:strong_rand_bytes(100),
    ?assertProp(version_id, "null", erlcloud_s3:put_object(Bucket, ?KEY, Block2, AnotherUser)),
    {Bucket, undefined, undefined}.

calc_storage_stats(CSNode) ->
    Begin = rtcs_dev:datetime(),
    %% FIXME: workaround for #766
    timer:sleep(1000),
    {ok, Res} = rtcs_exec:calculate_storage(1),
    logger:info("riak-cs-admin storage batch result: ~s", [Res]),
    ExpectRegexp = "Batch storage calculation started\.",
    ?assertMatch({match, _}, re:run(Res, ExpectRegexp)),
    true = rt:expect_in_log(CSNode, "Finished storage calculation"),
    %% FIXME: workaround for #766
    timer:sleep(1000),
    End = rtcs_dev:datetime(),
    {Begin, End}.

assert_storage_json_stats({Bucket, undefined, undefined}, Sample) ->
    ?assertEqual(notfound, rtcs_dev:json_get([list_to_binary(Bucket)], Sample));
assert_storage_json_stats({Bucket, ExpectedObjects, ExpectedBytes}, Sample) ->
    ?assertEqual(ExpectedObjects, rtcs_dev:json_get([list_to_binary(Bucket), <<"Objects">>],   Sample)),
    ?assertEqual(ExpectedBytes,   rtcs_dev:json_get([list_to_binary(Bucket), <<"Bytes">>],     Sample)),
    ?assert(rtcs_dev:json_get([<<"StartTime">>], Sample) =/= notfound),
    ?assert(rtcs_dev:json_get([<<"EndTime">>],   Sample) =/= notfound),
    ok.

assert_storage_xml_stats({Bucket, undefined, undefined}, Sample) ->
    ?assertEqual(undefined, proplists:get_value(Bucket, Sample));
assert_storage_xml_stats({Bucket, ExpectedObjects, ExpectedBytes}, Sample) ->
    ?assertEqual(ExpectedObjects, proplists:get_value('Objects', proplists:get_value(Bucket, Sample))),
    ?assertEqual(ExpectedBytes,   proplists:get_value('Bytes', proplists:get_value(Bucket, Sample))),
    ?assert(proplists:get_value('StartTime', Sample) =/= notfound),
    ?assert(proplists:get_value('EndTime', Sample)   =/= notfound),
    ok.

storage_stats_request(UserConfig, Begin, End) ->
    storage_stats_request(UserConfig, UserConfig, Begin, End).

storage_stats_request(SignUserConfig, UserConfig, Begin, End) ->
    {storage_stats_json_request(SignUserConfig, UserConfig, Begin, End),
     storage_stats_xml_request(SignUserConfig, UserConfig, Begin, End)}.

storage_stats_json_request(SignUserConfig, UserConfig, Begin, End) ->
    Samples = samples_from_json_request(SignUserConfig, UserConfig, {Begin, End}),
    ?assertEqual(1, length(Samples)),
    [Sample] = Samples,
    logger:debug("Storage sample[json]: ~p", [Sample]),
    Sample.

storage_stats_xml_request(SignUserConfig, UserConfig, Begin, End) ->
    Samples = samples_from_xml_request(SignUserConfig, UserConfig, {Begin, End}),
    ?assertEqual(1, length(Samples)),
    [Sample] = Samples,
    ParsedSample = to_proplist_stats(Sample),
    logger:debug("Storage sample[xml]: ~p", [ParsedSample]),
    ParsedSample.

samples_from_json_request(SignUserConfig, UserConfig, {Begin, End}) ->
    KeyId = UserConfig#aws_config.access_key_id,
    StatsKey = string:join(["usage", KeyId, "bj", Begin, End], "/"),
    GetResult = erlcloud_s3:get_object("riak-cs", StatsKey, SignUserConfig),
    Usage = jsx:decode(proplists:get_value(content, GetResult), [{return_maps, false}]),
    logger:debug("Usage Response[json]: ~p", [Usage]),
    rtcs_dev:json_get([<<"Storage">>, <<"Samples">>], Usage).

samples_from_xml_request(SignUserConfig, UserConfig, {Begin, End}) ->
    KeyId = UserConfig#aws_config.access_key_id,
    StatsKey = string:join(["usage", KeyId, "bx", Begin, End], "/"),
    GetResult = erlcloud_s3:get_object("riak-cs", StatsKey, SignUserConfig),
    {Usage, _Rest} = xmerl_scan:string(binary_to_list(proplists:get_value(content, GetResult))),
    logger:debug("Usage Response[xml]: ~p", [Usage]),
    xmerl_xpath:string("//Storage/Samples/Sample",Usage).

to_proplist_stats(Sample) ->
    lists:foldl(fun extract_bucket/2, [], Sample#xmlElement.content)
        ++ lists:foldl(fun extract_slice/2, [], Sample#xmlElement.attributes).

extract_bucket(#xmlElement{name='Bucket', attributes=[#xmlAttribute{value=Bucket}], content=Content}, Acc) ->
    [{Bucket, lists:foldl(fun extract_usage/2,[], Content)}|Acc].

extract_slice(#xmlAttribute{name=Name, value=Value}, Acc) ->
    [{Name, Value}|Acc].

extract_usage(#xmlElement{name=Name, content=[Content]}, Acc) ->
    [{Name, extract_value(Content)}|Acc].

extract_value(#xmlText{value=Content}) ->
    list_to_integer(Content).
