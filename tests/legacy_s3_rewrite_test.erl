%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2015 Basho Technologies, Inc.  All Rights Reserved.
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

-module(legacy_s3_rewrite_test).

-export([confirm/0]).
-include_lib("erlcloud/include/erlcloud_aws.hrl").

-define(TEST_BUCKET, "legacy-s3-rewrite-test").

confirm() ->
    {{UserConfig, AdminUserId}, {RiakNodes, _CSNodes, _Stanchion}} =
        rtcs:setup(1, [{cs, cs_config()}]),
    ok = erlcloud_s3:create_bucket(?TEST_BUCKET, UserConfig),
    CsPortStr = integer_to_list(rtcs_config:cs_port(hd(RiakNodes))),

    Cmd = os:find_executable("make"),
    Args = ["test-auth-v2"],
    Env = [{"CS_HTTP_PORT",          CsPortStr},
           {"AWS_ACCESS_KEY_ID",     UserConfig#aws_config.access_key_id},
           {"AWS_SECRET_ACCESS_KEY", UserConfig#aws_config.secret_access_key},
           {"USER_ID",               AdminUserId},
           {"CS_BUCKET",             ?TEST_BUCKET}],
    WaitTime = 2 * rt_config:get(rt_max_wait_time),
    case rtcs_exec:cmd(Cmd, [{cd, "client_tests/python/boto_tests"}, {env, Env}, {args, Args}], WaitTime) of
        ok ->
            rtcs_dev:pass();
        {error, Reason} ->
            lager:error("Error : ~p", [Reason]),
            error({?MODULE, Reason})
    end.

cs_config() ->
    [
     {riak_cs,
      [
       {enforce_multipart_part_size, false},
       {max_buckets_per_user, 150},
       {rewrite_module, riak_cs_s3_rewrite_legacy},
       {auth_v4_enabled, false}
      ]
     }].
