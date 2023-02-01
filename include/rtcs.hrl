%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2021-2023 TI Tokyo    All Rights Reserved.
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

-ifndef(RTCS_HRL).
-define(RTCS_HRL, included).

-include_lib("erlcloud/include/erlcloud_aws.hrl").
-include_lib("eunit/include/eunit.hrl").

-define(assertHasBucket(B, UserConfig),
        ?assert(
           lists:any(
             fun(PL) -> proplists:get_value(name, PL) == B end,
             proplists:get_value(buckets, erlcloud_s3:list_buckets(UserConfig)))
          )
       ).
-define(assertNoBuckets(UserConfig),
        ?assertEqual([], proplists:get_value(buckets, erlcloud_s3:list_buckets(UserConfig)))).

-define(assert500(X),
        ?assertError({aws_error, {http_error, 500, _, _}}, (X))).
-define(assert403(X),
        ?assertError({aws_error, {http_error, 403, _, _}}, (X))).

-define(assertProp(Key, Expected, Props),
        ?assertEqual(Expected,
                     proplists:get_value(Key, Props))).

-endif.
