%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2016 Basho Technologies, Inc.  All Rights Reserved.
%%               2023 TI Tokyo    All Rights Reserved.
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

-module(error_response_test).

-export([confirm/0]).

-include("rtcs.hrl").

-define(BUCKET, "error-response-test").
-define(BUCKET2, "error-response-test2").
-define(KEY, "a").
-define(ErrNodeId, 2).

confirm() ->
    {{UserConfig, _}, {RiakNodes, CSNodes}} = rtcs_dev:setup(2),
    ErrCSNode = lists:nth(?ErrNodeId, CSNodes),
    ErrNode = lists:nth(?ErrNodeId, RiakNodes),
    ErrConfig = rtcs_clients:aws_config(UserConfig, [{port, rtcs_config:cs_port(ErrNode)}]),

    %% setup initial data
    ?assertEqual(ok, erlcloud_s3:create_bucket(?BUCKET, UserConfig)),
    SingleBlock = crypto:strong_rand_bytes(400),
    erlcloud_s3:put_object(?BUCKET, ?KEY, SingleBlock, UserConfig),

    %% verify response for timeout during getting a user.
    rt_intercept:add(ErrCSNode, {riak_cs_user, [{{get_user, 2}, get_user_timeout}]}),
    {'EXIT', {{aws_error, {http_error, 503, undefined, ErrorString}}, _StackTrace}} =
        catch erlcloud_s3:get_object(?BUCKET, ?KEY, ErrConfig),
    SubSs = ["<Code>ServiceUnavailable</Code>"],
    lists:all(
      fun(S) -> match =:= re:run(ErrorString, S) end,
      SubSs),

    rt_intercept:clean(ErrCSNode, riak_cs_riak_client),

    rt_intercept:add(ErrCSNode, {riak_cs_block_server, [{{get_block_local, 6}, get_block_local_timeout}]}),
    {'EXIT', {{aws_error, {http_error, 503, undefined, ErrorString2}}, _}} =
        catch erlcloud_s3:get_object(?BUCKET, ?KEY, ErrConfig),
    SubSs = ["<Code>ServiceUnavailable</Code>"],
    lists:all(
      fun(S) -> match =:= re:run(ErrorString2, S) end,
      SubSs),

    rt_intercept:clean(ErrCSNode, riak_cs_block_server),

    pass.
