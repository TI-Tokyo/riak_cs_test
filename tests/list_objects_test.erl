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
    {{UserConfig, _}, {RiakNodes, [CSNode|_], _}} =
        rtcs:setup(1, [{cs, [{riak_cs, [{fold_objects_for_list_keys, false}]}]}]),

    rtcs_dev:load_cs_modules_for_riak_pipe_fittings(
      CSNode, RiakNodes, [riak_cs_utils,
                          rcs_common_manifest_utils,
                          rcs_common_manifest_resolution,
                          riak_cs_storage,
                          riak_cs_storage_mr]),

    assert_v1(CSNode),
    list_objects_test_helper:test(UserConfig).

assert_v1(CSNode) ->
    false =:= rpc:call(CSNode, riak_cs_list_objects_utils, fold_objects_for_list_keys, []).
