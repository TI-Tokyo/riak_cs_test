%% Copyright (c) 2015 Basho Technologies, Inc.  All Rights Reserved.

-module(mb_trans2_test).

%% @doc `riak_test' module for testing transition from single bag configuration
%% to multiple bag one, another pattern with `cs_suites'.

-export([confirm/0]).
-export([transition_to_mb/2,
         set_uniform_weights/1]).

confirm() ->
    rt_config:set(console_log_level, info),
    NodesInMaster = 2,
    SetupRes = setup_single_bag(NodesInMaster),
    {ok, InitialState} = cs_suites:new(SetupRes),
    {ok, EvolvedState} = cs_suites:fold_with_state(InitialState, history(NodesInMaster)),
    {ok, _FinalState}  = cs_suites:cleanup(EvolvedState),
    rtcs_dev:pass().

custom_configs() ->
    %% This branch is only for debugging this module
    [{riak, [{bitcask, [{max_file_size, 4*1024*1024}]}]},
     {cs,   [{riak_cs, [{leeway_seconds, 1}]}]}].

history(NodesInMaster) ->
    [
     {cs_suites, run,                 ["single-bag"]},
     {?MODULE  , transition_to_mb,    [NodesInMaster]},
     {cs_suites, run,                 ["mb-disjoint"]},
     {?MODULE  , set_uniform_weights, []},
     {cs_suites, run,                 ["mb-uniform"]}
    ].

setup_single_bag(NodesInMaster) ->
    Tussle = {RiakNodes, [CSNode|_], _} = rtcs:setupNxMsingles(NodesInMaster, 4, custom_configs(), current),
    UserConfig = rtcs:setup_admin_user(4, current),

    rtcs_dev:load_cs_modules_for_riak_pipe_fittings(
      CSNode, RiakNodes, [riak_cs_utils,
                          rcs_common_manifest_utils,
                          rcs_common_manifest_resolution,
                          riak_cs_storage,
                          riak_cs_storage_mr]),

    {UserConfig, Tussle}.

transition_to_mb(NodesInMaster, State) ->
    RiakNodes = cs_suites:nodes_of(riak, State),
    CSNodes = cs_suites:nodes_of(cs, State),
    NodeList = lists:zip(CSNodes, RiakNodes),
    BagConf = rtcs_bag:conf(NodesInMaster, disjoint),
    rt:pmap(fun({CSNode, _RiakNode}) -> rtcs_exec:stop_cs(CSNode, current) end, NodeList),
    %% Because there are noises from poolboy shutdown at stopping riak-cs,
    %% truncate error log here and re-assert emptiness of error.log file later.
    rtcs:truncate_error_log(1),

    rt:pmap(fun({CSNode, RiakNode}) ->
                    N = rtcs_dev:node_id(RiakNode),
                    rtcs:set_conf({cs, current, N}, BagConf),
                    %% dev1 is the master cluster, so all CS nodes are configured as that
                    %% Also could be dev2, but not dev3 or later.
                    rtcs:set_advanced_conf({cs, current, N},
                                           [{riak_cs,
                                             [{riak_host, {"127.0.0.1", rtcs_config:pb_port(1)}}]}]),
                    rtcs_exec:start_cs(CSNode)
            end, NodeList),
    [ok = rt:wait_until_pingable(N) || N <- CSNodes],
    rt:setup_log_capture(hd(cs_suites:nodes_of(cs, State))),
    rtcs_bag:set_weights(rtcs_bag:weights(disjoint)),
    {0, ListWeightRes} = rtcs_bag:list_weight(),
    logger:info("Weight disjoint: ~s", [ListWeightRes]),
    {ok, State}.

set_uniform_weights(State) ->
    rtcs_bag:set_weights(uniform_all_weights()),
    {0, ListWeightRes} = rtcs_bag:list_weight(),
    logger:info("Weight disjoint: ~s", [ListWeightRes]),
    {ok, State}.

uniform_all_weights() ->
    [{all, "bag-A", 100},
     {all, "bag-B", 100},
     {all, "bag-C", 100},
     {all, "bag-D", 100},
     {all, "bag-E", 100}].
