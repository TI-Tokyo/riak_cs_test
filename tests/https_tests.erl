%% -------------------------------------------------------------------
%%
%% Copyright (c) 2016 Basho Technologies, Inc.
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

-module(https_tests).

-export([confirm/0]).

confirm() ->
    {ok, _} = application:ensure_all_started(ssl),
    {{UserConfig, _}, {_, [CSNode0]}} = rtcs_dev:setup(1),
    rtcs_dev:stop(CSNode0),
    CSConfig = [{ssl, [{certfile, "./etc/cert.pem"}, {keyfile, "./etc/key.pem"}]}],
    rtcs_config:set_configs(1,
                            rtcs_config:configs([{cs, [{riak_cs, CSConfig}]}], current),
                            current),
    rtcs_dev:start(CSNode0),

    % logger:info("UserConfig: ~p", [UserConfig]),
    ok = verify_cs1025(UserConfig),
    pass.

verify_cs1025(UserConfig) ->
    B = <<"booper">>,
    K = <<"drooper">>,
    K2 = <<"super">>,
    logger:info("Creating a bucket ~s", [B]),
    rtcs_object:upload(UserConfig, {https, 0}, B, <<>>),
    logger:info("Creating a source object to copy, ~s", [K]),
    rtcs_object:upload(UserConfig, {https, 42}, B, K),
    logger:info("Trying copy from ~s to ~s", [K, K2]),
    rtcs_object:upload(UserConfig, https_copy, B, K2, K).
