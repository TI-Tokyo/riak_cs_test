%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2015 Basho Technologies, Inc.
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

-module(legacy_s3_rewrite_test).

-export([confirm/0]).

-include_lib("erlcloud/include/erlcloud_aws.hrl").



confirm() ->
    {{UserConfig, AdminUserId}, {RiakNodes, _CSNodes}} =
        rtcs_dev:setup(1, [{cs, cs_config()}]),

    CsPortStr = integer_to_list(rtcs_config:cs_port(hd(RiakNodes))),

    Args = ["test-auth-v2"],
    Env = [{"CS_HTTP_PORT",          CsPortStr},
           {"AWS_ACCESS_KEY_ID",     UserConfig#aws_config.access_key_id},
           {"AWS_SECRET_ACCESS_KEY", UserConfig#aws_config.secret_access_key},
           {"USER_ID",               AdminUserId}],



    case rtcs_dev:cmd({spawn_executable, os:find_executable("make")},
                      [{cd, "client_tests/python/boto_tests"}, {env, Env}, {args, Args}]) of
        {ok, _} ->
            pass;
        {error, Reason} ->
            logger:error("Error : ~p", [Reason])
    end.

cs_config() ->
    [{riak_cs,
      [{enforce_multipart_part_size, false},
       {max_buckets_per_user, 150},
       {auth_v4_enabled, false},
       {rewrite_module, riak_cs_s3_rewrite_legacy}
      ]
     }
    ].
