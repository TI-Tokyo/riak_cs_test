%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2016 Basho Technologies, Inc.  All Rights Reserved.
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

-module(rtcs_admin).

-export([storage_stats_json_request/4,
         create_user/2,
         create_user/3,
         create_user/4,
         create_user_rpc/3,
         create_admin_user/1,
         update_user/5,
         get_user/4,
         list_users/4,
         make_authorization/5,
         make_authorization/6,
         make_authorization/7
        ]).

-include_lib("erlcloud/include/erlcloud_aws.hrl").

-spec storage_stats_json_request(#aws_config{}, #aws_config{}, string(), string()) ->
          [{string(), {non_neg_integer(), non_neg_integer()}}].
storage_stats_json_request(AdminConfig, UserConfig, Begin, End) ->
    Samples = samples_from_json_request(AdminConfig, UserConfig, {Begin, End}),
    logger:debug("Storage samples[json]: ~p", [Samples]),
    {struct, Slice} = latest(Samples, undefined),
    by_bucket_list(Slice, []).

%% Kludge for SSL testing
create_user_rpc(Node, Key, Secret) ->
    User = "admin",
    Email = "admin@me.com",

    %% You know this is a kludge, user creation via RPC
    _Res = rpc:call(Node, riak_cs_user, create_user, [User, Email, Key, Secret]),
    {rtcs_clients:aws_config(Key, Secret, rtcs_config:cs_port(1)), undefined}.

-spec create_admin_user(atom()) -> {#aws_config{}, binary()}.
create_admin_user(Node) ->
    create_admin_with_policy(Node).
create_admin_with_policy(Node) ->
    Port = rtcs_config:cs_port(Node),
    Cmd = io_lib:format("~s/dev/dev1/riak-cs/priv/tools/create-admin -p ~b -q",
                        [rtcs_config:devpath(cs, current), Port]),
    {ok, Stdout} = rtcs_dev:cmd(Cmd),
    [KeyId, KeySecret, CanonicalId] = string:tokens(lists:droplast(binary_to_list(Stdout)), " "),
    {rtcs_clients:aws_config(KeyId, KeySecret, Port), CanonicalId}.


-spec create_user(atom(), non_neg_integer()) -> #aws_config{}.
create_user(Node, UserIndex) ->
    User = "Test User" ++ integer_to_list(UserIndex),
    Email = lists:flatten(io_lib:format("test_user_~b_~b@basho.com", [UserIndex, os:system_time(millisecond)])),
    {UserConfig, Id} = create_user(rtcs_config:cs_port(Node), Email, User),
    logger:info("Created user ~s (~s) on ~s:", [User, Email, Node]),
    logger:info("KeyId     : ~s", [UserConfig#aws_config.access_key_id]),
    logger:info("KeySecret : ~s", [UserConfig#aws_config.secret_access_key]),
    logger:info("UserId    : ~s", [Id]),
    UserConfig.

-spec create_user(non_neg_integer(), string(), string()) -> {#aws_config{}, string()}.
create_user(Port, EmailAddr, Name) ->
    %% create_user(Port, undefined, EmailAddr, Name).
    create_user(Port, rtcs_clients:aws_config("admin-key", "admin-secret", Port), EmailAddr, Name).

-spec create_user(non_neg_integer(), string(), string(), string()) -> {#aws_config{}, string()}.
create_user(Port, UserConfig = #aws_config{}, EmailAddr, Name) ->
    logger:debug("Trying to create user ~p", [EmailAddr]),
    Resource = "/riak-cs/user",
    ReqBody = "{\"email\":\"" ++ EmailAddr ++  "\", \"name\":\"" ++ Name ++"\"}",
    {_Status, _ResHeader, ResBody} =
        rtcs_clients:s3_request(UserConfig,
                                post, Resource, [], "",
                                {ReqBody, "application/json"}, []),
    logger:debug("ResBody: ~p", [ResBody]),
    JsonData = mochijson2:decode(ResBody),
    [KeyId, KeySecret, Id] = [binary_to_list(rtcs_dev:json_get([K], JsonData)) ||
                                 K <- [<<"key_id">>, <<"key_secret">>, <<"canonical_id">>]],
    {rtcs_clients:aws_config(KeyId, KeySecret, Port), Id}.



-spec update_user(#aws_config{}, non_neg_integer(), string(), string(), string()) -> {non_neg_integer(), string()}.
update_user(UserConfig, _Port, Resource, ContentType, UpdateDoc) ->
    {Status, _ResHeader, ResBody} =
        rtcs_clients:s3_request(UserConfig, put, Resource, [], "",
                                {UpdateDoc, ContentType}, []),
    logger:debug("ResBody: ~s", [ResBody]),
    {Status, ResBody}.

-spec get_user(#aws_config{}, non_neg_integer(), string(), string()) -> string().
get_user(UserConfig, _Port, Resource, AcceptContentType) ->
    logger:debug("Retreiving user record"),
    Headers = [{"Accept", AcceptContentType}],
    {Status, _ResHeader, ResBody} =
        rtcs_clients:s3_request(UserConfig, get, Resource, [], "", "", Headers),
    logger:debug("ResBody: ~s", [ResBody]),
    {Status, ResBody}.

-spec list_users(#aws_config{}, non_neg_integer(), string(), string()) -> string().
list_users(UserConfig, _Port, Resource, AcceptContentType) ->
    Headers = [{"Accept", AcceptContentType}],
    {_Status, _ResHeader, ResBody} =
        rtcs_clients:s3_request(UserConfig, get, Resource, [], "", "", Headers),
    ResBody.


-spec(make_authorization(string(), string(), string(), #aws_config{}, string()) -> string()).
make_authorization(Method, Resource, ContentType, Config, Date) ->
    make_authorization(Method, Resource, ContentType, Config, Date, []).

-spec(make_authorization(string(), string(), string(), #aws_config{}, string(), [{string(), string()}]) -> string()).
make_authorization(Method, Resource, ContentType, Config, Date, AmzHeaders) ->
    make_authorization(s3, Method, Resource, ContentType, Config, Date, AmzHeaders).

-spec(make_authorization(atom(), string(), string(), string(), #aws_config{}, string(), [{string(), string()}]) -> string()).
make_authorization(Type, Method, Resource, ContentType, Config, Date, AmzHeaders) ->
    Prefix = case Type of
                 s3 -> "AWS";
                 velvet -> "MOSS"
             end,
    StsAmzHeaderPart = [[K, $:, V, $\n] || {K, V} <- AmzHeaders],
    STS = iolist_to_binary(
            [as_string(Method), $\n, [], $\n, ContentType, $\n, Date, $\n, StsAmzHeaderPart, Resource]),
    Signature =
        base64:encode_to_string(crypto:mac(hmac, sha, Config#aws_config.secret_access_key, STS)),
    lists:flatten([Prefix, " ", Config#aws_config.access_key_id, $:, Signature]).
as_string(A) when is_atom(A) ->
    string:to_upper(atom_to_list(A));
as_string(A) -> A.


latest([], {_, Candidate}) ->
    Candidate;
latest([Sample | Rest], undefined) ->
    StartTime = rtcs_dev:json_get([<<"StartTime">>], Sample),
    latest(Rest, {StartTime, Sample});
latest([Sample | Rest], {CandidateStartTime, Candidate}) ->
    StartTime = rtcs_dev:json_get([<<"StartTime">>], Sample),
    NewCandidate = case StartTime < CandidateStartTime of
                       true -> {CandidateStartTime, Candidate};
                       _    -> {StartTime, Sample}
                   end,
    latest(Rest, NewCandidate).

by_bucket_list([], Acc) ->
    lists:sort(Acc);
by_bucket_list([{<<"StartTime">>, _} | Rest], Acc) ->
    by_bucket_list(Rest, Acc);
by_bucket_list([{<<"EndTime">>, _} | Rest], Acc) ->
    by_bucket_list(Rest, Acc);
by_bucket_list([{BucketBin, {struct,[{<<"Objects">>, Objs},
                                     {<<"Bytes">>, Bytes}]}} | Rest],
               Acc) ->
    by_bucket_list(Rest, [{binary_to_list(BucketBin), {Objs, Bytes}}|Acc]).

samples_from_json_request(AdminConfig, UserConfig, {Begin, End}) ->
    KeyId = UserConfig#aws_config.access_key_id,
    StatsKey = string:join(["usage", KeyId, "bj", Begin, End], "/"),
    GetResult = erlcloud_s3:get_object("riak-cs", StatsKey, AdminConfig),
    Usage = mochijson2:decode(proplists:get_value(content, GetResult)),
    rtcs_dev:json_get([<<"Storage">>, <<"Samples">>], Usage).

