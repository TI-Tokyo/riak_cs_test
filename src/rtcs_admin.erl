%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2016 Basho Technologies, Inc.  All Rights Reserved.
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
         make_authorization/7,
         aws_config/2,
         aws_config/3]).

-include_lib("eunit/include/eunit.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").
-include_lib("xmerl/include/xmerl.hrl").

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
    {aws_config(Key, Secret, rtcs_config:cs_port(1)), undefined}.

-spec create_admin_user(atom()) -> {#aws_config{}, binary()}.
create_admin_user(Node) ->
    User = "admin",
    Email = "admin@me.com",
    %% must match the values in client_tests/python/boto_test.py

    {UserConfig, Id} = create_user(rtcs_config:cs_port(Node), Email, User),
    logger:info("Created Riak CS Admin account with:", []),
    logger:info("KeyId     : ~s", [UserConfig#aws_config.access_key_id]),
    logger:info("KeySecret : ~s", [UserConfig#aws_config.secret_access_key]),
    logger:info("UserId    : ~s", [Id]),
    {UserConfig, Id}.

-spec create_user(atom(), non_neg_integer()) -> #aws_config{}.
create_user(Node, UserIndex) ->
    User = "Test User" ++ integer_to_list(UserIndex),
    Email = lists:flatten(io_lib:format("test_user_~b@basho.com", [UserIndex])),
    {UserConfig, Id} = create_user(rtcs_config:cs_port(Node), Email, User),
    logger:info("Created user ~s (~s):", [User, Email]),
    logger:info("KeyId     : ~s", [UserConfig#aws_config.access_key_id]),
    logger:info("KeySecret : ~s", [UserConfig#aws_config.secret_access_key]),
    logger:info("UserId    : ~s", [Id]),
    UserConfig.

-spec create_user(non_neg_integer(), string(), string()) -> {#aws_config{}, string()}.
create_user(Port, EmailAddr, Name) ->
    %% create_user(Port, undefined, EmailAddr, Name).
    create_user(Port, aws_config("admin-key", "admin-secret", Port), EmailAddr, Name).

-spec create_user(non_neg_integer(), string(), string(), string()) -> {#aws_config{}, string()}.
create_user(Port, UserConfig = #aws_config{}, EmailAddr, Name) ->
    logger:debug("Trying to create user ~p", [EmailAddr]),
    Resource = "/riak-cs/user",
    ReqBody = "{\"email\":\"" ++ EmailAddr ++  "\", \"name\":\"" ++ Name ++"\"}",
    {_ResHeader, ResBody} =
        s3_request(UserConfig,
                   post, "", Resource, [], "",
                   {ReqBody, "application/json"}, []),
    logger:debug("ResBody: ~s", [ResBody]),
    JsonData = mochijson2:decode(ResBody),
    [KeyId, KeySecret, Id] = [binary_to_list(rtcs:json_get([K], JsonData)) ||
                                 K <- [<<"key_id">>, <<"key_secret">>, <<"id">>]],
    {aws_config(KeyId, KeySecret, Port), Id}.

-spec update_user(#aws_config{}, non_neg_integer(), string(), string(), string()) -> string().
update_user(UserConfig, _Port, Resource, ContentType, UpdateDoc) ->
    {_ResHeader, ResBody} = s3_request(
                              UserConfig, put, "", Resource, [], "",
                              {UpdateDoc, ContentType}, []),
    logger:debug("ResBody: ~s", [ResBody]),
    ResBody.

-spec get_user(#aws_config{}, non_neg_integer(), string(), string()) -> string().
get_user(UserConfig, _Port, Resource, AcceptContentType) ->
    logger:debug("Retreiving user record"),
    Headers = [{"Accept", AcceptContentType}],
    {_ResHeader, ResBody} = s3_request(
                              UserConfig, get, "", Resource, [], "", "", Headers),
    logger:debug("ResBody: ~s", [ResBody]),
    ResBody.

-spec list_users(#aws_config{}, non_neg_integer(), string(), string()) -> string().
list_users(UserConfig, _Port, Resource, AcceptContentType) ->
    Headers = [{"Accept", AcceptContentType}],
    {_ResHeader, ResBody} = s3_request(
                              UserConfig, get, "", Resource, [], "", "", Headers),
    ResBody.

s3_request(#aws_config{s3_host = S3Host,
                       s3_scheme = S3Scheme,
                       hackney_client_options = #hackney_client_options{proxy = {_ProxyHost, ProxyPort}}} = Config,
           Method, Host, Path, Subresources, Params, POSTData, Headers) ->
    {ContentMD5, ContentType, Body} =
        case POSTData of
            {PD, CT} -> {base64:encode(crypto:hash(md5, PD)), CT, PD}; PD -> {"", "", PD}
        end,
    AmzHeaders = lists:filter(fun ({"x-amz-" ++ _, V}) when V =/= undefined -> true; (_) -> false end, Headers),
    Date = httpd_util:rfc1123_date(erlang:localtime()),
    EscapedPath = url_encode_loose(Path),
    Authorization = make_authorization(Config, Method, ContentMD5, ContentType,
                                       Date, AmzHeaders, Host, EscapedPath, Subresources),
    FHeaders = [Header || {_, Value} = Header <- Headers, Value =/= undefined],
    RequestHeaders = [{"date", Date}, {"authorization", Authorization}|FHeaders] ++
        case ContentMD5 of
            "" -> [];
            _ -> [{"content-md5", binary_to_list(ContentMD5)}]
        end,
    RequestURI =
        lists:flatten([S3Scheme,
                       case Host of "" -> ""; _ -> [Host, $.] end,
                       S3Host, ":", integer_to_list(ProxyPort),
                       EscapedPath,
                       format_subresources(Subresources),
                       if
                           Params =:= [] -> "";
                           Subresources =:= [] -> [$?, uri_string:compose_query(Params)];
                           true -> [$&, uri_string:compose_query(Params)]
                       end
                      ]),
    Options = [{proxy_host, "127.0.0.1"}, {proxy_port, ProxyPort}],
    {ok, _Status, ResponseHeaders, ResponseBody} =
        ibrowse:send_req(RequestURI, [{"content-type", ContentType} | RequestHeaders],
                         Method, Body, Options),
    {ResponseHeaders, ResponseBody}.

url_encode_loose(Binary) when is_binary(Binary) ->
    url_encode_loose(binary_to_list(Binary));
url_encode_loose(String) ->
    url_encode_loose(String, []).
url_encode_loose([], Accum) ->
    lists:reverse(Accum);
url_encode_loose([Char|String], Accum)
  when Char >= $A, Char =< $Z;
       Char >= $a, Char =< $z;
       Char >= $0, Char =< $9;
       Char =:= $-; Char =:= $_;
       Char =:= $.; Char =:= $~;
       Char =:= $/; Char =:= $: ->
    url_encode_loose(String, [Char|Accum]);
url_encode_loose([Char|String], Accum)
  when Char >=0, Char =< 255 ->
    url_encode_loose(String, [hex_char(Char rem 16), hex_char(Char div 16),$%|Accum]).

hex_char(C) when C >= 0, C =< 9 -> $0 + C;
hex_char(C) when C >= 10, C =< 15 -> $A + C - 10.

format_subresources([]) ->
    [];
format_subresources(Subresources) ->
    [$? | string:join(lists:sort([format_subresource(Subresource) ||
                                     Subresource <- Subresources]),
                      "&")].

format_subresource({Subresource, Value}) when is_list(Value) ->
    Subresource ++ "=" ++ Value;
format_subresource({Subresource, Value}) when is_integer(Value) ->
    Subresource ++ "=" ++ integer_to_list(Value);
format_subresource(Subresource) ->
    Subresource.

make_authorization(#aws_config{access_key_id = KeyId,
                               secret_access_key = SecretKey},
                   Method, ContentMD5, ContentType, Date, AmzHeaders,
                   Host, Resource, Subresources) ->
    CanonizedAmzHeaders =
        [[Name, $:, Value, $\n] || {Name, Value} <- lists:sort(AmzHeaders)],
    StringToSign = [string:to_upper(atom_to_list(Method)), $\n,
                    ContentMD5, $\n,
                    ContentType, $\n,
                    Date, $\n,
                    CanonizedAmzHeaders,
                    case Host of "" -> ""; _ -> [$/, Host] end,
                    Resource,
                    format_subresources(Subresources)
                   ],
    Signature = base64:encode(crypto:mac(hmac, sha, SecretKey, StringToSign)),
    ["AWS ", KeyId, $:, Signature].

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
    StringToSign = [Method, $\n, [], $\n, ContentType, $\n, Date, $\n,
                    StsAmzHeaderPart, Resource],
    logger:debug("StringToSign: ~s", [StringToSign]),
    Signature =
        base64:encode_to_string(crypto:hash(sha, Config#aws_config.secret_access_key, StringToSign)),
    lists:flatten([Prefix, " ", Config#aws_config.access_key_id, $:, Signature]).

-spec aws_config(string(), string(), non_neg_integer()) -> #aws_config{}.
aws_config(Key, Secret, Port) ->
    #aws_config{access_key_id = Key,
                secret_access_key = Secret,
                s3_scheme = "http://",
                hackney_client_options = #hackney_client_options{proxy = {"http://127.0.0.1", Port}}}.

-spec aws_config(#aws_config{}, [{atom(), term()}]) -> #aws_config{}.
aws_config(UserConfig, []) ->
    UserConfig;
aws_config(UserConfig, [{port, Port}|Props]) ->
    aws_config(UserConfig#aws_config{hackney_client_options = #hackney_client_options{proxy = {"localhost", Port}}},
               Props);
aws_config(UserConfig, [{key, KeyId}|Props]) ->
    aws_config(UserConfig#aws_config{access_key_id = KeyId},
               Props);
aws_config(UserConfig, [{secret, Secret}|Props]) ->
    aws_config(UserConfig#aws_config{secret_access_key = Secret},
               Props).


latest([], {_, Candidate}) ->
    Candidate;
latest([Sample | Rest], undefined) ->
    StartTime = rtcs:json_get([<<"StartTime">>], Sample),
    latest(Rest, {StartTime, Sample});
latest([Sample | Rest], {CandidateStartTime, Candidate}) ->
    StartTime = rtcs:json_get([<<"StartTime">>], Sample),
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
    rtcs:json_get([<<"Storage">>, <<"Samples">>], Usage).

