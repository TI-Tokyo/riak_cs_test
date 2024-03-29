%% -------------------------------------------------------------------
%%
%% Copyright (c) 2015 Basho Technologies, Inc.
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

-module(mb_trans2_test).

%% @doc `riak_test' module for testing transition from single bag configuration
%% to multiple bag one, another pattern with `cs_suites'.

-export([confirm/0]).
-export([transition_to_mb/2,
         set_uniform_weights/1]).

confirm() ->
    NodesInMaster = 2,
    SetupRes = setup_single_bag(NodesInMaster),
    {ok, InitialState} = cs_suites:new(SetupRes),
    {ok, EvolvedState} = cs_suites:fold_with_state(InitialState, history(NodesInMaster)),
    {ok, _FinalState}  = cs_suites:cleanup(EvolvedState),
    pass.

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
    Tussle = rtcs_dev:setupNxMsingles(NodesInMaster, 4, custom_configs(), current),

    UserConfig = rtcs_dev:setup_admin_user(4, current),

    {UserConfig, Tussle}.

transition_to_mb(NodesInMaster, State) ->
    RiakNodes = cs_suites:nodes_of(riak, State),
    CSNodes = cs_suites:nodes_of(cs, State),
    BagConf = rtcs_bag:conf(NodesInMaster, disjoint),

    rt:pmap(fun rtcs_dev:stop/1, CSNodes),
    %% Because there are noises from poolboy shutdown at stopping riak-cs,
    %% truncate error log here and re-assert emptiness of error.log file later.
    rtcs_dev:truncate_error_log(1),

    rt:pmap(fun(RiakNode) ->
                    N = rtcs_dev:node_id(RiakNode),
                    rtcs_dev:set_conf({cs, current, N}, BagConf),
                    %% dev1 is the master cluster, so all CS nodes are configured as that
                    %% Also could be dev2, but not dev3 or later.
                    rtcs_dev:set_advanced_conf(
                      {cs, current, N},
                      [{riak_cs, [{riak_host, {"127.0.0.1", rtcs_config:pb_port(1)}}]}]
                     )
            end, RiakNodes),
    [N1|Nn] = CSNodes,
    rtcs_dev:start(N1), rt:wait_until_pingable(N1),
    rt:pmap(fun(N) -> rtcs_dev:start(N), rt:wait_until_pingable(N) end, Nn),

    rt:setup_log_capture(hd(CSNodes)),
    rtcs_bag:set_weights(rtcs_bag:weights(disjoint)),
    ListWeightRes = rtcs_bag:list_weight(),
    logger:info("Weight disjoint: ~s", [ListWeightRes]),
    {ok, State}.

set_uniform_weights(State) ->
    rtcs_bag:set_weights(uniform_all_weights()),
    ListWeightRes = rtcs_bag:list_weight(),
    logger:info("Weight disjoint: ~s", [ListWeightRes]),
    {ok, State}.

uniform_all_weights() ->
    [{all, "bag-A", 100},
     {all, "bag-B", 100},
     {all, "bag-C", 100},
     {all, "bag-D", 100},
     {all, "bag-E", 100}].
