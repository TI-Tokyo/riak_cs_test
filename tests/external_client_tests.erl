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

-module(external_client_tests).

-export([confirm/0]).

-include_lib("erlcloud/include/erlcloud_aws.hrl").

-define(EXTRA_TEST_BUCKET, "go-test-bucket").

confirm() ->
    {{UserConfig, AdminUserId}, {RiakNodes, [CSNode]}} =
        rtcs_dev:setup(1, [{cs, cs_config()}]),

    rtcs_dev:load_cs_modules_for_riak_pipe_fittings(
      CSNode, RiakNodes, [riak_cs_utils,
                          rcs_common_manifest_utils,
                          rcs_common_manifest_resolution]),

    CsPortStr = integer_to_list(rtcs_config:cs_port(hd(RiakNodes))),

    Args = ["test-client"],
    Env = [{"CS_HTTP_PORT",          CsPortStr},
           {"AWS_ACCESS_KEY_ID",     UserConfig#aws_config.access_key_id},
           {"AWS_SECRET_ACCESS_KEY", UserConfig#aws_config.secret_access_key},
           {"USER_ID",               AdminUserId}],

    ok = erlcloud_s3:create_bucket(?EXTRA_TEST_BUCKET, UserConfig),
    %% this is how I debug individual clients/cases:
    %% 1. Uncomment the sleep below:
    %% timer:sleep(3333333333),
    %% cd ../client_tests/python and do something like:
    %% you@localhost:/path/to/riak_cs_test/client_tests/python $ AWS_ACCESS_KEY_ID=8SFYPUPEUCS599HZG-X0 \
    %%       AWS_SECRET_ACCESS_KEY=kySUm9lCtsbAzjiAZtF3an1QrbbmaAFV0bYuTQ \
    %%       USER_ID=9337d19ad75800a10b171f4bf1e4eeeadfec3eb432a15f3a75d528ebf9d3921d \
    %%       CS_HTTP_PORT=15018  RCST_VERBOSE=1 python -m unittest boto_test_versioning

    case rtcs_dev:cmd({spawn_executable, os:find_executable("make")},
                      [{cd, "tests/external_clients"}, {env, Env}, {args, Args}]) of
        {ok, _} ->
            pass;
        {error, Reason} ->
            logger:error("Error : ~p", [Reason])
    end.

cs_config() ->
    [{riak_cs,
      [{enforce_multipart_part_size, false},
       {max_buckets_per_user, 300},
       {auth_v4_enabled, true}
      ]
     }
    ].
