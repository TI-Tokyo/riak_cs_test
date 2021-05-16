%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2013 Basho Technologies, Inc.  All Rights Reserved.
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

-module(list_objects_test).

%% @doc Integration test for list the contents of a bucket

-export([confirm/0]).
-include_lib("eunit/include/eunit.hrl").

-define(TEST_BUCKET, "riak-test-bucket").

confirm() ->
    rtcs:set_conf(cs, [{"fold_objects_for_list_keys", "off"}]),
    {UserConfig, {[RiakNode|_], [CSNode|_], _Stanchion}} = rtcs:setup(1),

    %% add an extra path for riak_pipe to be able to load custom beams
    %% for its map and reduce phases, defined as Mod and Fun in the
    %% specs returned by riak_cs_list_objects_fsm:mapred_query/0.
    ExtPath = filename:dirname(rpc:call(CSNode, code, which, [riak_cs_utils])),
    rpc:call(RiakNode, code, add_pathz, [ExtPath]),

    %% and explicitly load some accessory modules (riak_cs_utils
    %% makes calls into funs in those modules), because riak_pipe only
    %% loads those mentioned in the specs:
    rpc:call(RiakNode, code, load_file, [riak_cs_utils]),
    rpc:call(RiakNode, code, load_file, [riak_cs_manifest_utils]),
    rpc:call(RiakNode, code, load_file, [riak_cs_manifest_resolution]),

    assert_v1(CSNode),
    list_objects_test_helper:test(UserConfig).

assert_v1(CSNode) ->
    false =:= rpc:call(CSNode, riak_cs_list_objects_utils, fold_objects_for_list_keys, []).
