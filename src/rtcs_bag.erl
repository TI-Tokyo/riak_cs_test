%% -------------------------------------------------------------------
%%
%% Copyright (c) 2014 Basho Technologies, Inc.
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
%% -------------------------------------------------------------------

-module(rtcs_bag).

-export([set_conf/2,
         conf/2,
         conf/3,
         configs/1,
         flavored_setup/1,
         bags/1,
         bags/2,
         assert_manifest_in_single_bag/4,
         assert_block_in_single_bag/4,
         assert_no_manifest_in_any_bag/3,
         assert_no_block_in_any_bag/3,
         high_low/1,
         set_weights/1,
         set_zero_weight/0,
         weights/1,
         list_weight/0,
         bag_refresh/1
        ]).


-include("riak_cs.hrl").

%% Setup utilities

set_conf(NumNodes, BagFlavor) ->
    BagConf = conf(NumNodes, BagFlavor),
    rtcs_dev:set_conf(cs, BagConf),
    ok.

conf(NumNodes, BagFlavor) ->
    conf(NumNodes, 1, BagFlavor).

conf(NumNodes, NodeOffset, BagFlavor) ->
    Bags = bags(NumNodes, NodeOffset, BagFlavor),
    [{"riak_host", "127.0.0.1:" ++ integer_to_list(rtcs_config:pb_port(NodeOffset))}] ++
    [{"supercluster.member." ++ BagId, IP ++ ":" ++ integer_to_list(Port)} ||
        {BagId, IP, Port} <- Bags].

configs(MultiBags) ->
      [{cs, [{riak_cs_multibag, [{bags, MultiBags}]}]}].

%% BagFlavor is `disjoint' only for now
%% TODO: Other nodes than CS node 1 have wrong riak_pb_port configuration.
flavored_setup(#{num_nodes := NumNodes,
                 flavor := {multibag, BagFlavor},
                 configs := CustomConfigs,
                 vsn := current = Vsn,
                 preconfigured := Preconfigured}) ->
    rtcs_dev:create_or_restore_config_backups(NumNodes, Vsn),
    set_conf(NumNodes, BagFlavor),
    Singltons = 4,
    SetupResult = rtcs_dev:setupNxMsingles(NumNodes, Singltons, CustomConfigs, Vsn, Preconfigured),
    set_weights(weights(BagFlavor)),
    SetupResult;
flavored_setup(#{num_nodes := NumNodes,
                 flavor := {multibag, BagFlavor},
                 configs := CustomConfigs,
                 vsn := Vsn,
                 preconfigured := Preconfigured}) ->
    MultiBags = bags(NumNodes, BagFlavor),
    BagConfigs = configs(MultiBags),
    Singltons = 4,
    SetupResult = rtcs_dev:setupNxMsingles(NumNodes, Singltons, rtcs_config:merge(CustomConfigs, BagConfigs), Vsn,
                                           Preconfigured),
    set_weights(weights(BagFlavor)),
    SetupResult.

bags(disjoint) ->
    bags(1, disjoint).

bags(NumNodes, disjoint) ->
    bags(NumNodes, 1, disjoint).

bags(NumNodes, NodeOffset, disjoint) ->
    [{"bag-A", "127.0.0.1", rtcs_config:pb_port(NodeOffset)},
     {"bag-B", "127.0.0.1", rtcs_config:pb_port(NodeOffset + NumNodes)},
     {"bag-C", "127.0.0.1", rtcs_config:pb_port(NodeOffset + NumNodes + 1)},
     {"bag-D", "127.0.0.1", rtcs_config:pb_port(NodeOffset + NumNodes + 2)},
     {"bag-E", "127.0.0.1", rtcs_config:pb_port(NodeOffset + NumNodes + 3)}];
bags(NumNodes, NodeOffset, shared) ->
    [{"bag-A", "127.0.0.1", rtcs_config:pb_port(NodeOffset)},
     {"bag-B", "127.0.0.1", rtcs_config:pb_port(NodeOffset + NumNodes)},
     {"bag-C", "127.0.0.1", rtcs_config:pb_port(NodeOffset + NumNodes + 1)}].

weights(disjoint) ->
    [{manifest, "bag-B", 100},
     {manifest, "bag-C", 100},
     {block,    "bag-D", 100},
     {block,    "bag-E", 100}];
weights(shared) ->
    [{all, "bag-A", 100},
     {all, "bag-B", 100},
     {all, "bag-C", 100}].

set_zero_weight() ->
    set_weights([{all, "bag-A", 0}]).

set_weights(BagFlavor) when is_atom(BagFlavor) ->
    set_weights(weights(BagFlavor));
set_weights(Weights) ->
    [bag_weight(1, Kind, BagId, Weight) || {Kind, BagId, Weight} <- Weights].

%% %% Return Riak node IDs, one per cluster.  For disjoint, 1 for the
%% %% master bag and last 4 non-master's (singleton clusters)
%% riak_id_per_cluster(NumNodes, {multibag, disjoint}) ->
%%     [1 | lists:seq(NumNodes + 1, NumNodes + 4)].

%% %% CsBucket and CsKey may be needed if there are multiple bags for manifests (or blocks)
%% pbc({multibag, disjoint}, Kind, RiakNodes, _Seed)
%%   when Kind =/= objects andalso Kind =/= blocks ->
%%     rt:pbc(hd(RiakNodes));
%% pbc({multibag, disjoint}, ObjectKind, RiakNodes, Seed) ->
%%     [BagE, BagD, BagC, BagB | _RestNodes] = lists:reverse(RiakNodes),
%%     HighLow = high_low(Seed),
%%     case {ObjectKind, HighLow} of
%%         {objects, low}  -> rt:pbc(BagB);
%%         {objects, high} -> rt:pbc(BagC);
%%         {blocks,  low}  -> rt:pbc(BagD);
%%         {blocks,  high} -> rt:pbc(BagE)
%%     end.

%% Utility for two bags with 100 weight each.
%% `low' means former bag (in binary order) and `high' does latter.
high_low(Seed) ->
    Point = sha_int(Seed) rem 200 + 1,
    case Point of
        _ when Point =< 100 -> low;
        _                   -> high
    end.

%% Calculate SHA integer from seed.
%% This logic depnds on `riak_cs_multibag_server' implementation.
-spec sha_int(Seed::term()) -> integer().
sha_int({B, K, ?MANIFEST{uuid=UUID}}) ->
    sha_int2({ensure_binary(B), ensure_binary(K), UUID});
sha_int({B, K, UUID}) ->
    sha_int2({ensure_binary(B), ensure_binary(K), UUID});
sha_int(Seed) ->
    sha_int2(ensure_binary(Seed)).

sha_int2(Seed) ->
    SeedBin = term_to_binary(Seed),
    <<SHA:160>> = crypto:hash(sha, SeedBin),
    SHA.

ensure_binary(V) when is_list(V) ->
    list_to_binary(V);
ensure_binary(V) when is_binary(V) ->
    V.

%% pbc_start_link(Port) ->
%%     {ok, Pid} = riakc_pb_socket:start_link("127.0.0.1", Port),
%%     Pid.

multibagcmd(Path, N, Args) ->
    lists:flatten(io_lib:format("~s-supercluster ~s", [riakcs_binpath(Path, N), Args])).
riakcs_binpath(Prefix, N) ->
    io_lib:format("~s/dev/dev~b/riak-cs/bin/riak-cs", [Prefix, N]).

list_weight() ->
    list_weight(1).

list_weight(N) ->
    Cmd = multibagcmd(rt_config:get(rtcs_config:cs_current()), N, io_lib:format("~s", [weight])),
    {ok, Res} = rtcs_dev:cmd(Cmd),
    Res.

bag_weight(N, Kind, BagId, Weight) ->
    SubCmd = case Kind of
                 all ->      "weight";
                 manifest -> "weight-manifest";
                 block ->    "weight-block"
             end,
    Cmd = multibagcmd(rt_config:get(rtcs_config:cs_current()), N,
                             io_lib:format("~s ~s ~B", [SubCmd, BagId, Weight])),
    rtcs_dev:cmd(Cmd).

bag_refresh(N) ->
    Cmd = multibagcmd(rt_config:get(rtcs_config:cs_current()), N, "refresh"),
    rtcs_dev:cmd(Cmd).

%% Assertion utilities

%% Assert manifest riak object of given bkey exists only in
%% `ExpectedBag' and does not exist in other bags.  `ExpectedBag'
%% should be calculated by multibag configuration and weights.
assert_manifest_in_single_bag(Bucket, Key, AllBags, ExpectedBag) ->
    NotExistingBags = AllBags -- [ExpectedBag],
    RiakBucket = <<"0o:", (crypto:hash(md5, Bucket))/binary>>,
    case assert_only_in_single_bag(ExpectedBag, NotExistingBags, RiakBucket, Key) of
        {error, Reason} ->
            logger:error("assert_manifest_in_single_bag for ~w/~w error: ~p",
                         [Bucket, Key, Reason]),
            {error, {Bucket, Key, Reason}};
        Object ->
            [[{UUID, M}]] = [binary_to_term(V) || V <- riakc_obj:get_values(Object)],
            {UUID, M}
    end.

%% Assert block riak object of given manifest with seq=0 exists only
%% in `ExpectedBag' and does not exist in other bags.  `ExpectedBag'
%% should be calculated by multibag configuration and weights.
assert_block_in_single_bag(Bucket, Manifest, AllBags, ExpectedBag) ->
    NotExistingBags = AllBags -- [ExpectedBag],
    RiakBucket = <<"0b:", (crypto:hash(md5, Bucket))/binary>>,
    UUIDForBlock = block_uuid(Manifest),
    RiakKey = <<UUIDForBlock/binary, 0:32>>,
    case assert_only_in_single_bag(ExpectedBag, NotExistingBags, RiakBucket, RiakKey) of
        {error, Reason} ->
            {_, Key} = Manifest?MANIFEST.bkey,
            logger:error("assert_block_in_single_bag for ~w/~w [~w] error: ~p",
                         [Bucket, Key, UUIDForBlock, Reason]),
            {error, {Bucket, Key, UUIDForBlock}, Reason};
        _Object ->
            ok
    end.

%% Assert manifest riak object of given bkey does not exist in any
%% bag.
assert_no_manifest_in_any_bag(Bucket, Key, AllBags) ->
    RiakBucket = <<"0o:", (crypto:hash(md5, Bucket))/binary>>,
    case assert_not_in_other_bags(AllBags, RiakBucket, Key) of
        ok -> ok;
        {error, Reason} ->
            logger:error("assert_no_manifest_in_any_bag for ~w/~w error: ~p",
                         [Bucket, Key, Reason]),
            {error, {Bucket, Key, Reason}}
    end.

%% Assert block riak object of given manifest with seq=0 does not
%% exist in any bag.
assert_no_block_in_any_bag(Bucket, Manifest, AllBags) ->
    RiakBucket = <<"0b:", (crypto:hash(md5, Bucket))/binary>>,
    UUIDForBlock = block_uuid(Manifest),
    RiakKey = <<UUIDForBlock/binary, 0:32>>,
    case assert_not_in_other_bags(AllBags, RiakBucket, RiakKey) of
        ok -> ok;
        {error, Reason} ->
            {_, Key} = Manifest?MANIFEST.bkey,
            logger:error("assert_no_block_in_any_bag for ~w/~w [~w] error: ~p",
                         [Bucket, Key, UUIDForBlock, Reason]),
            {error, {Bucket, Key, UUIDForBlock}, Reason}
    end.

block_uuid(M) ->
    case proplists:get_value(multipart, M?MANIFEST.props) of
        undefined ->
            M?MANIFEST.uuid;
        MpM ->
            %% Take UUID of the first block of the first part manifest
            (hd(MpM?MULTIPART_MANIFEST.parts))?PART_MANIFEST.part_id
    end.

-spec assert_only_in_single_bag(ExpectedBag::binary(), NotExistingBags::[binary()],
                                RiakBucket::binary(), RiakKey::binary()) ->
                                       riakc_obj:riakc_obj().
%% Assert BKey
%% - exists in ExpectedBag and
%% - does not exists in any NotExistingBags.
%% Also returns a riak object which is found in ExpectedBags.
assert_only_in_single_bag(ExpectedBag, NotExistingBags, RiakBucket, RiakKey) ->
    case assert_in_expected_bag(ExpectedBag, RiakBucket, RiakKey) of
        {error, Reason} ->
            {error, Reason};
        Obj ->
            case assert_not_in_other_bags(NotExistingBags, RiakBucket, RiakKey) of
                {error, Reason2} ->
                    {error, Reason2};
                _ ->
                    Obj
            end
    end.

assert_in_expected_bag(ExpectedBag, RiakBucket, RiakKey) ->
    case get_riakc_obj(ExpectedBag, RiakBucket, RiakKey) of
        {ok, Object} ->
            logger:info("~p/~p is found at ~s", [RiakBucket, RiakKey, ExpectedBag]),
            Object;
        {error, notfound} ->
            {error, {not_found_in_expected_bag, ExpectedBag}}
    end.

assert_not_in_other_bags([], _RiakBucket, _RiakKey) ->
    ok;
assert_not_in_other_bags([NotExistingBag | Rest], RiakBucket, RiakKey) ->
    case get_riakc_obj(NotExistingBag, RiakBucket, RiakKey) of
        {error, notfound} ->
            assert_not_in_other_bags(Rest, RiakBucket, RiakKey);
        Res ->
            logger:info("~p/~p is found at ~s", [RiakBucket, RiakKey, NotExistingBag]),
            {error, {found_in_unexpected_bag, NotExistingBag, Res}}
    end.

get_riakc_obj(Bag, B, K) ->
    Riakc = rt:pbc(Bag),
    Result = riakc_pb_socket:get(Riakc, B, K),
    riakc_pb_socket:stop(Riakc),
    Result.
