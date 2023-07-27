%% -------------------------------------------------------------------
%%
%% Copyright (c) 2023 TI Tokyo    All Rights Reserved.
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

-module(rtcs_clients).

-export([s3_request/7,
         curl_request/4, curl_request/5, curl_request/6,
         aws_config/2, aws_config/3
        ]).

-include_lib("erlcloud/include/erlcloud_aws.hrl").

-type method() :: get | post | put | delete.
-type http_code() :: non_neg_integer().
-type header() :: {string(), string()}.


-spec s3_request(#aws_config{}, method(), string(), [string()],
                 proplists:proplist(), iodata(), [header()]) ->
          {http_code(), [header()], string()}.
s3_request(#aws_config{s3_host = S3Host,
                       s3_port = S3Port,
                       s3_scheme = S3Scheme,
                       hackney_client_options = #hackney_client_options{proxy = {_ProxyHost, ProxyPort}}} = Config,
           Method, Path, Subresource, Params, POSTData, Headers) ->
    {ContentMD5, ContentType, Body} =
        case POSTData of
            {PD, CT} -> {base64:encode(crypto:hash(md5, PD)), CT, PD};
            PD -> {"", "", PD}
        end,
    AmzHeaders = lists:filter(
                   fun ({"x-amz-" ++ _, V}) when V =/= undefined -> true;
                       (_) -> false
                   end, Headers),
    Date = httpd_util:rfc1123_date(erlang:localtime()),
    EscapedPath = url_encode_loose(Path),
    Authorization = make_authorization(Config, Method, ContentMD5, ContentType,
                                       Date, AmzHeaders, "", EscapedPath, Subresource),
    FHeaders = [Header || {_, Value} = Header <- Headers, Value =/= undefined],
    RequestHeaders = [{"date", Date}, {"authorization", Authorization}|FHeaders] ++
        case ContentMD5 of
            "" -> [];
            _ -> [{"content-md5", binary_to_list(ContentMD5)}]
        end,
    RequestURI =
        lists:flatten(
          [S3Scheme, "",
           S3Host, ":", integer_to_list(S3Port),
           EscapedPath, Subresource,
           if Params =:= [] -> "";
              el/=se -> [$&, uri_string:compose_query(Params)]
           end
          ]),
    Options = [{proxy_host, "127.0.0.1"}, {proxy_port, ProxyPort}],
    {ok, Status, ResponseHeaders, ResponseBody} =
        ibrowse:send_req(RequestURI, [{"content-type", ContentType} | RequestHeaders],
                         Method, Body, Options),
    {list_to_integer(Status), ResponseHeaders, ResponseBody}.

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

make_authorization(#aws_config{access_key_id = KeyId,
                               secret_access_key = SecretKey},
                   Method, ContentMD5, ContentType, Date, AmzHeaders,
                   Host, Resource, Subresource) ->
    CanonizedAmzHeaders =
        [[Name, $:, Value, $\n] || {Name, Value} <- lists:sort(AmzHeaders)],
    StringToSign = [string:to_upper(atom_to_list(Method)), $\n,
                    ContentMD5, $\n,
                    ContentType, $\n,
                    Date, $\n,
                    CanonizedAmzHeaders,
                    case Host of "" -> ""; _ -> [$/, Host] end,
                    Resource,
                    Subresource
                   ],
    Signature = base64:encode(crypto:mac(hmac, sha, SecretKey, StringToSign)),
    ["AWS ", KeyId, $:, Signature].



-spec aws_config(string(), string(), non_neg_integer()) -> #aws_config{}.
aws_config(Key, Secret, Port) ->
    #aws_config{http_client = hackney,
                access_key_id = Key,
                secret_access_key = Secret,
                s3_scheme = "http://",
                timeout = 30000,
                hackney_client_options = #hackney_client_options{proxy = {"127.0.0.1", Port}}}.

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

-spec curl_request(#aws_config{}, method(), string(), [header()]) ->
          {ok, iodata() | {error, term()}}.
curl_request(UserConfig, Method, Resource, AmzHeaders) ->
    curl_request(UserConfig, Method, Resource, AmzHeaders, [], cs).

-spec curl_request(#aws_config{}, method(), string(), [header()], string()) ->
          {ok, iodata() | {error, term()}}.
curl_request(UserConfig, Method, Resource, AmzHeaders, PostData) ->
    curl_request(UserConfig, Method, Resource, AmzHeaders, PostData, cs).

-spec curl_request(#aws_config{}, method(), string(), [header()], string(), cs | stanchion) ->
          {ok, iodata() | {error, term()}}.
curl_request(#aws_config{hackney_client_options = #hackney_client_options{proxy = {_, CSPort}}} = UserConfig,
             Method, Resource, AmzHeaders, PostData, Type) ->
    {Port, Prefix} =
        case Type of
            cs ->
                {CSPort, s3};
            stanchion ->
                {rtcs_config:stanchion_port(), velvet}
        end,
    ContentType = "application/octet-stream",
    Date = httpd_util:rfc1123_date(),
    Auth = rtcs_admin:make_authorization(
             Prefix, Method, Resource, ContentType, UserConfig, Date, AmzHeaders),
    HeaderArgs = [io_lib:format("-H '~s: ~s' ", [K, V]) ||
                     {K, V} <- [{"Date", Date}, {"Authorization", Auth},
                                {"Content-Type", ContentType} | AmzHeaders]],
    Cmd = io_lib:format(
            "curl -X ~s -s ~s ~s"
            " 'http://127.0.0.1:~b~s'",
            [Method, HeaderArgs, maybe_post_data(Method, PostData), Port, Resource]),
    rtcs_dev:cmd(Cmd).

maybe_post_data(M, Data) when M == post; M == 'POST' ->
    iolist_to_binary(["--data-binary '", Data, "'"]);
maybe_post_data(_, _) ->
    <<>>.
