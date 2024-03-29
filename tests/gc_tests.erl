%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2014 Basho Technologies, Inc.
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

-module(gc_tests).

%% @doc `riak_test' module for testing garbage collection

-export([confirm/0]).

-include_lib("eunit/include/eunit.hrl").
-include("riak_cs.hrl").

%% keys for non-multipart objects
-define(TEST_BUCKET,        "riak-test-bucket").
-define(TEST_KEY,          "riak_test_key").
-define(TEST_KEY_MP,        "riak_test_mp").
-define(TEST_KEY_BAD_STATE, "riak_test_key_bad_state").
-define(TIMESLICES,        5).

confirm() ->
    NumNodes = 1,
    {{UserConfig, _}, {RiakNodes, CSNodes}} = rtcs_dev:setup(NumNodes),
    %% Set up to grep logs to verify messages
    rt:setup_log_capture(hd(CSNodes)),

    rtcs_exec:gc(1, "set-interval infinity"),
    rtcs_exec:gc(1, "set-leeway 1"),
    rtcs_exec:gc(1, "cancel"),

    logger:info("Test GC run under an invalid state manifest..."),
    {GCKey, {BKey, UUID}} = setup_obj(RiakNodes, UserConfig),

    %% Ensure the leeway has expired
    timer:sleep(2000),

    {ok, Result} = rtcs_exec:gc(1, "earliest-keys"),
    logger:debug("~p", [Result]),
    ?assert(string:str(binary_to_list(Result), "GC keys in") > 0),

    ok = verify_gc_run(hd(CSNodes), GCKey),
    ok = verify_riak_object_remaining_for_bad_key(RiakNodes, GCKey, {BKey, UUID}),

    logger:info("Test repair script (repair_gc_bucket.erl) with more invlaid states..."),
    ok = put_more_bad_keys(RiakNodes, UserConfig),
    %% Ensure the leeway has expired
    timer:sleep(2000),
    RiakIDs = rtcs_dev:riak_id_per_cluster(NumNodes),
    [repair_gc_bucket(ID) || ID <- RiakIDs],
    ok = verify_gc_run2(hd(CSNodes)),

    %% Determinisitc GC test

    %% Create keys not to be deleted
    setup_normal_obj([{"spam", 42}, {"ham", 65536}, {"egg", 7}], UserConfig),
    timer:sleep(1000), %% Next timestamp...

    %% Create keys to be deleted
    Start = os:timestamp(),
    [begin
         setup_normal_obj([{"hop", 42}, {"step", 65536}, {"jump", 7}], UserConfig),
         timer:sleep(2000)
     end || _ <- lists:seq(0,?TIMESLICES) ],
    End = os:timestamp(),

    timer:sleep(1000), %% Next timestamp...
    setup_normal_obj([{"spam", 42}, {"ham", 65536}, {"egg", 7}], UserConfig),

    verify_partial_gc_run(hd(CSNodes), RiakNodes, Start, End),
    pass.

setup_normal_obj(ObjSpecs, UserConfig) ->
    %% Put and delete some objects
    [begin
         Block = crypto:strong_rand_bytes(Size),
         Key = ?TEST_KEY ++ Suffix,
         erlcloud_s3:put_object(?TEST_BUCKET, Key, Block, UserConfig),
         erlcloud_s3:delete_object(?TEST_BUCKET, Key, UserConfig)
     end || {Suffix, Size} <- ObjSpecs].

setup_obj(RiakNodes, UserConfig) ->
    %% Setup bucket
    logger:info("User is valid on the cluster, and has no buckets"),
    ?assertEqual([], proplists:get_value(buckets, erlcloud_s3:list_buckets(UserConfig))),
    logger:info("creating bucket ~p", [?TEST_BUCKET]),
    ?assertEqual(ok, erlcloud_s3:create_bucket(?TEST_BUCKET, UserConfig)),

    setup_normal_obj([{"1", 100}, {"2", 200}, {"3", 0}], UserConfig),

    %% Put and delete, but modified to pretend it is in wrong state
    SingleBlock = crypto:strong_rand_bytes(400),
    erlcloud_s3:put_object(?TEST_BUCKET, ?TEST_KEY_BAD_STATE, SingleBlock, UserConfig),
    erlcloud_s3:delete_object(?TEST_BUCKET, ?TEST_KEY_BAD_STATE, UserConfig),
    %% Change the state in the manifest in gc bucket to active.
    %% See https://github.com/basho/riak_cs/issues/827#issuecomment-54567839
    GCPbc = rtcs_dev:pbc(RiakNodes, objects, ?TEST_BUCKET),
    {ok, GCKeys} = riakc_pb_socket:list_keys(GCPbc, ?GC_BUCKET),
    BKey = {list_to_binary(?TEST_BUCKET), list_to_binary(?TEST_KEY_BAD_STATE)},
    logger:info("Changing state to active ~p, ~p", [?TEST_BUCKET, ?TEST_KEY_BAD_STATE]),
    {ok, GCKey, UUID} = change_state_to_active(GCPbc, BKey, GCKeys),

    %% Put and delete some more objects
    setup_normal_obj([{"Z", 0}, {"Y", 150}, {"X", 1}], UserConfig),

    riakc_pb_socket:stop(GCPbc),
    {GCKey, {BKey, UUID}}.

change_state_to_active(_Pbc, TargetBKey, []) ->
    logger:warning("Target BKey ~p not found in GC bucket", [TargetBKey]),
    {error, notfound};
change_state_to_active(Pbc, TargetBKey, [GCKey|Rest]) ->
    {ok, Obj0} = riakc_pb_socket:get(Pbc, ?GC_BUCKET, GCKey),
    Manifests = twop_set:to_list(binary_to_term(riakc_obj:get_value(Obj0))),
    case [{UUID, M?MANIFEST{state=active}} ||
              {UUID, M} <- Manifests,
              M?MANIFEST.bkey =:= TargetBKey] of
        [] ->
            change_state_to_active(Pbc, TargetBKey, Rest);
        [{TargetUUID, TargetManifest}] ->
            logger:info("Target BKey ~p found in GC bucket ~p", [TargetBKey, GCKey]),
            NewManifestSet =
                lists:foldl(fun twop_set:add_element/2, twop_set:new(),
                            [{TargetUUID,
                              TargetManifest?MANIFEST{
                                               state = active,
                                               delete_marked_time=undefined,
                                               delete_blocks_remaining=undefined}} |
                             lists:keydelete(TargetUUID, 1, Manifests)]),
            UpdObj = riakc_obj:update_value(Obj0, term_to_binary(NewManifestSet)),
            ok = riakc_pb_socket:put(Pbc, UpdObj),
            logger:info("Bad state manifests have been put at ~p: ~p",
                        [GCKey, twop_set:to_list(NewManifestSet)]),
            {ok, GCKey, TargetUUID}
    end.

put_more_bad_keys(RiakNodes, UserConfig) ->
    %% Put and delete some objects
    [begin
         Block = crypto:strong_rand_bytes(10),
         Key = ?TEST_KEY ++ integer_to_list(Suffix),
         erlcloud_s3:put_object(?TEST_BUCKET, Key, Block, UserConfig),
         erlcloud_s3:delete_object(?TEST_BUCKET, Key, UserConfig)
     end || Suffix <- lists:seq(100, 199)],
    GCPbc = rtcs_dev:pbc(RiakNodes, objects, ?TEST_BUCKET),
    {ok, GCKeys} = riakc_pb_socket:list_keys(GCPbc, ?GC_BUCKET),
    BadGCKeys = put_more_bad_keys(GCPbc, GCKeys, []),
    logger:info("Bad state manifests have been put at ~p", [BadGCKeys]),
    ok.

put_more_bad_keys(_Pbc, [], BadGCKeys) ->
    BadGCKeys;
put_more_bad_keys(Pbc, [GCKey|Rest], BadGCKeys) ->
    case riakc_pb_socket:get(Pbc, ?GC_BUCKET, GCKey) of
        {error, notfound} ->
            put_more_bad_keys(Pbc, Rest, BadGCKeys);
        {ok, Obj0} ->
            Manifests = twop_set:to_list(binary_to_term(riakc_obj:get_value(Obj0))),
            NewManifests = [{UUID, M?MANIFEST{state = active,
                                              delete_marked_time=undefined,
                                              delete_blocks_remaining=undefined}} ||
                               {UUID, M} <- Manifests],
            NewManifestSet =
                lists:foldl(fun twop_set:add_element/2, twop_set:new(), NewManifests),
            UpdObj = riakc_obj:update_value(Obj0, term_to_binary(NewManifestSet)),
            ok = riakc_pb_socket:put(Pbc, UpdObj),
            put_more_bad_keys(Pbc, Rest, [GCKey | BadGCKeys])
    end.

repair_gc_bucket(RiakNodeID) ->
    PbPort = integer_to_list(rtcs_config:pb_port(RiakNodeID)),
    {ok, <<>>} = rtcs_exec:exec_priv_escript(
                   1, "repair_gc_bucket.erl",
                   "--host 127.0.0.1 --port " ++ PbPort ++ " --leeway-seconds 1 --page-size 5",
                   #{by => cs}),
    ok.

verify_gc_run(Node, GCKey) ->
    rtcs_exec:gc(1, "batch 1"),
    logger:info("Check log, warning for invalid state and info for GC finish"),
    true = rt:expect_in_log(Node,
                            "Invalid state manifest in GC bucket at <<\""
                            ++ binary_to_list(GCKey) ++ "\">>, "
                            ++ "b/k:v \"" ++ ?TEST_BUCKET ++ "/" ++ ?TEST_KEY_BAD_STATE
                            ++ ":null\""),
    true = rt:expect_in_log(Node,
                            "Finished garbage collection: \\d+ msec, "
                            "\\d batch_count, 0 batch_skips, "
                            "7 manif_count, 4 block_count"),
    ok.

verify_gc_run2(Node) ->
    rtcs_exec:gc(1, "batch 1"),
    logger:info("Check collected count =:= 101, 1 from setup_obj, "
                "100 from put_more_bad_keys."),
    true = rt:expect_in_log(Node,
                            "Finished garbage collection: \\d+ msec, "
                            "\\d+ batch_count, 0 batch_skips, "
                            "101 manif_count, 101 block_count"),
    ok.

%% Verify riak objects in gc buckets, manifest, block are all remaining.
verify_riak_object_remaining_for_bad_key(RiakNodes, GCKey, {{Bucket, Key}, UUID}) ->
    {ok, _BlockObj} = rc_helper:get_riakc_obj(RiakNodes, blocks, Bucket, {Key, UUID, 0}),
    {ok, _ManifestObj} = rc_helper:get_riakc_obj(RiakNodes, objects, Bucket, Key),

    GCPbc = rtcs_dev:pbc(RiakNodes, objects, Bucket),
    {ok, FileSetObj} = riakc_pb_socket:get(GCPbc, ?GC_BUCKET, GCKey),
    Manifests = twop_set:to_list(binary_to_term(riakc_obj:get_value(FileSetObj))),
    {UUID, Manifest} = lists:keyfind(UUID, 1, Manifests),
    riakc_pb_socket:stop(GCPbc),
    logger:info("As expected, BAD manifest in GC bucket remains,"
                " stand off orphan manfiests/blocks: ~p", [Manifest]),
    ok.

verify_partial_gc_run(CSNode, RiakNodes,
                      {MegaSec0, Sec0, _},
                      {MegaSec1, Sec1, _}) ->
    Start0 = MegaSec0 * 1000000 + Sec0,
    End0 = MegaSec1 * 1000000 + Sec1,
    Interval = erlang:max(1, (End0 - Start0) div ?TIMESLICES),
    Starts = [ {Start0 + N * Interval, Start0 + (N+1) * Interval}
               || N <- lists:seq(0, ?TIMESLICES-1) ] ++
        [{Start0 + ?TIMESLICES * Interval, End0}],

    [begin
         %% We have to clear log as the message 'Finished garbage
         %% col...' has been output many times before, during this
         %% test.
         rt:reset_log(CSNode),

         logger:debug("GC: (start, end) = (~p, ~p)", [S0, E0]),
         S = iso8601(S0),
         E = iso8601(E0),
         BatchCmd = "batch -s " ++ S ++ " -e " ++ E,
         rtcs_exec:gc(1, BatchCmd),

         true = rt:expect_in_log(CSNode,
                                 "Finished garbage collection: \\d+ msec, "
                                 "\\d+ batch_count, 0 batch_skips, "
                                 "\\d+ manif_count, \\d+ block_count")
     end || {S0, E0} <- Starts],
    logger:info("GC target period: (~p, ~p)", [Start0, End0]),
    %% Reap!
    timer:sleep(3000),
    GCPbc = rtcs_dev:pbc(RiakNodes, objects, ?TEST_BUCKET),
    {ok, Keys} = riakc_pb_socket:list_keys(GCPbc, ?GC_BUCKET),
    logger:debug("Keys: ~p", [Keys]),
    StartKey = list_to_binary(integer_to_list(Start0)),
    EndKey = list_to_binary(integer_to_list(End0)),
    EndKeyHPF = fun(Key) -> EndKey < Key end,
    StartKeyLPF = fun(Key) -> Key < StartKey end,
    BPF = fun(Key) -> StartKey < Key andalso Key < EndKey end,

    logger:debug("Remaining Keys: ~p", [Keys]),
    logger:debug("HPF result: ~p", [lists:filter(EndKeyHPF, Keys)]),
    logger:debug("LPF result: ~p", [lists:filter(StartKeyLPF, Keys)]),
    ?assertEqual(3, length(lists:filter(EndKeyHPF, Keys))),
    ?assertEqual(3, length(lists:filter(StartKeyLPF, Keys))),
    ?assertEqual([], lists:filter(BPF, Keys)),
    ok.

%% Copy from rts:iso8601/1
iso8601(Timestamp) when is_integer(Timestamp) ->
    GregSec = Timestamp + 719528 * 86400,
    Datetime = calendar:gregorian_seconds_to_datetime(GregSec),
    {{Y,M,D},{H,I,S}} = Datetime,
    io_lib:format("~4..0b~2..0b~2..0bT~2..0b~2..0b~2..0bZ",
                  [Y, M, D, H, I, S]).
