%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2013 Basho Technologies, Inc.
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

-module(list_objects_v2_test).

%% @doc Integration test for list the contents of a bucket

-export([confirm/0]).

-include_lib("eunit/include/eunit.hrl").

confirm() ->
    {{UserConfig, _}, {RiakNodes, [_CSNode|_]}} =
        rtcs_dev:setup(1),

    ok = list_to_non_existent_bucket_many_times(RiakNodes),
    list_objects_test_helper:test(UserConfig).


list_to_non_existent_bucket_many_times(RiakNodes) ->
    [?assertEqual("404",
                  list_objects_by_anonymous(
                    RiakNodes,
                    "non-existent-bucket-" ++ integer_to_list(I))) ||
        I <- lists:seq(1, 30)],
    ok.

list_objects_by_anonymous(RiakNodes, Bucket) ->
    Port = rtcs_config:cs_port(hd(RiakNodes)),
    %% --write-out '%{http_code}': output http response status code to stdout
    Cmd = "curl -s --write-out '%{http_code}' -o /dev/null http://localhost:" ++
        integer_to_list(Port) ++ "/" ++ Bucket,
    os:cmd(Cmd).



