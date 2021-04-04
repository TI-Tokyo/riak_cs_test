%% riak_test in riak_cs-2.1 used an old, forked version of erlcloud,
%% with erlcloud_s3:s3_request/9 customized and made exportable. That
%% version, https://github.com/basho/erlcloud/releases/tag/0.4.6,
%% could not be (easily) built in otp-22, so here's some functions
%% manually copied from it.
%%
%% The only post-copy change I made is include {?RCS_REWRITE_HEADER,
%% Path}.

-module(rtcs_s3).

-export([new/2, new/3, new/4, new/5, new/8,
         s3_request/9, get_object/3]).

-include("rtcs_erlcloud_aws.hrl").

-define(RCS_REWRITE_HEADER, "x-rcs-rewrite-path").


-spec new(string(), string()) -> aws_config().
new(AccessKeyID, SecretAccessKey) ->
    #aws_config{
     access_key_id=AccessKeyID,
     secret_access_key=SecretAccessKey
    }.

-spec new(string(), string(), string()) -> aws_config().
new(AccessKeyID, SecretAccessKey, Host) ->
    #aws_config{
     access_key_id=AccessKeyID,
     secret_access_key=SecretAccessKey,
     s3_host=Host
    }.


-spec new(string(), string(), string(), non_neg_integer()) -> aws_config().
new(AccessKeyID, SecretAccessKey, Host, Port) ->
    #aws_config{
     access_key_id=AccessKeyID,
     secret_access_key=SecretAccessKey,
     s3_host=Host,
     s3_port=Port
    }.

-spec new(string(), string(), string(), non_neg_integer(), string()) -> aws_config().
new(AccessKeyID, SecretAccessKey, Host, Port, Protocol) ->
    #aws_config{
     access_key_id=AccessKeyID,
     secret_access_key=SecretAccessKey,
     s3_host=Host,
     s3_port=Port,
     s3_prot=Protocol
    }.

-spec new(string(),
          string(),
          string(),
          non_neg_integer(),
          string(),
          string(),
          non_neg_integer(),
          proplists:proplist()) -> aws_config().
new(AccessKeyID, SecretAccessKey, Host, Port, Protocol, ProxyHost, ProxyPort,
    HttpOptions) ->
    #aws_config{
     access_key_id=AccessKeyID,
     secret_access_key=SecretAccessKey,
     s3_host=Host,
     s3_port=Port,
     s3_prot=Protocol,
     http_options=[{proxy_host, ProxyHost}, {proxy_port, ProxyPort},
                   {max_sessions, 50}, {max_pipeline_size, 1},
                   {connect_timeout, 5000}, {inactivity_timeout, 240000}]
                  ++ HttpOptions
    }.



s3_request(Config, Method, Host, Path, Subresources, Params, POSTData, Headers, GetOptions) ->
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
    RequestHeaders = [{"date", Date}, {"authorization", Authorization},
                      {?RCS_REWRITE_HEADER, Path} | FHeaders] ++
        case ContentMD5 of
            "" -> [];
            _ -> [{"content-md5", binary_to_list(ContentMD5)}]
        end,
    RequestURI = lists:flatten([
                                Config#aws_config.s3_prot,
                                "://",
                                case Host of "" -> ""; _ -> [Host, $.] end,
                                Config#aws_config.s3_host, port_spec(Config),
                                EscapedPath,
                                format_subresources(Subresources),
                                if
                                    Params =:= [] -> "";
                                    Subresources =:= [] -> [$?, make_query_string(Params)];
                                    true -> [$&, make_query_string(Params)]
                                end
                               ]),
    Timeout = 240000,
    Options = Config#aws_config.http_options,
    Response = case Method of
                   get ->
                       ibrowse:send_req(RequestURI, RequestHeaders, Method, [],
                                        Options ++ GetOptions, Timeout);
                   delete ->
                       ibrowse:send_req(RequestURI, RequestHeaders, Method,
                                        [], Options, Timeout);
                   _ ->
                       NewHeaders = [{"content-type", ContentType} | RequestHeaders],
                       ibrowse:send_req(RequestURI, NewHeaders, Method, Body,
                                        Options, Timeout)
               end,
    io:format("aaaaaaaaaaaaa ~p\n", [Response]),
    case Response of
        {ok, Status, ResponseHeaders, ResponseBody} ->
             S = list_to_integer(Status),
             case S >= 200 andalso S =< 299 of
                 true ->
                     {ResponseHeaders, ResponseBody};
                 false ->
                     erlang:error({aws_error, {http_error, S, "", ResponseBody}})
             end;
        {error, Error} ->
            erlang:error({aws_error, {socket_error, Error}})
    end.

make_authorization(Config, Method, ContentMD5, ContentType, Date, AmzHeaders,
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
    Signature = base64:encode(crypto:hmac(sha, Config#aws_config.secret_access_key, StringToSign)),
    ["AWS ", Config#aws_config.access_key_id, $:, Signature].

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

port_spec(#aws_config{s3_port=80}) ->
    "";
port_spec(#aws_config{s3_port=Port}) ->
    [":", erlang:integer_to_list(Port)].



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



-spec get_object(string(), string(), proplists:proplist() | aws_config()) -> proplists:proplist().
get_object(BucketName, Key, Config)
  when is_record(Config, aws_config) ->
    get_object(BucketName, Key, [], Config).

-spec get_object(string(), string(), proplists:proplist(), aws_config()) -> proplists:proplist().
get_object(BucketName, Key, Options, Config) ->
    fetch_object(get, BucketName, Key, Options, Config).

-spec fetch_object(atom(), string(), string(), proplists:proplist(), aws_config()) -> proplists:proplist().
fetch_object(Method, BucketName, Key, Options, Config) ->
    RequestHeaders = [{"Range", proplists:get_value(range, Options)},
                      {"Accept", proplists:get_value(accept, Options)},
                      {"If-Modified-Since", proplists:get_value(if_modified_since, Options)},
                      {"If-Unmodified-Since", proplists:get_value(if_unmodified_since, Options)},
                      {"If-Match", proplists:get_value(if_match, Options)},
                      {"If-None-Match", proplists:get_value(if_none_match, Options)}],
    Subresource = case proplists:get_value(version_id, Options) of
                      undefined -> "";
                      Version   -> [{"versionId", Version}]
                  end,
    {Headers, Body} = s3_request(Config, Method, BucketName, [$/|Key], Subresource, [], <<>>, RequestHeaders, [{response_format, binary}]),
    [{etag, proplists:get_value("ETag", Headers)},
     {content_length, proplists:get_value("Content-Length", Headers)},
     {content_type, proplists:get_value("Content-Type", Headers)},
     {delete_marker, list_to_existing_atom(proplists:get_value("x-amz-delete-marker", Headers, "false"))},
     {version_id, proplists:get_value("x-amz-version-id", Headers, "null")},
     {content, Body},
     {headers, Headers} |
     extract_metadata(Headers)].

make_query_string(Params) ->
    string:join([[Key, "=", url_encode(value_to_string(Value))]
                 || {Key, Value} <- Params, Value =/= none, Value =/= undefined], "&").

value_to_string(Integer) when is_integer(Integer) -> integer_to_list(Integer);
value_to_string(Atom) when is_atom(Atom) -> atom_to_list(Atom);
value_to_string(Binary) when is_binary(Binary) -> Binary;
value_to_string(String) when is_list(String) -> String.

url_encode(Binary) when is_binary(Binary) ->
    url_encode(binary_to_list(Binary));
url_encode(String) ->
    url_encode(String, []).
url_encode([], Accum) ->
    lists:reverse(Accum);
url_encode([Char|String], Accum)
  when Char >= $A, Char =< $Z;
       Char >= $a, Char =< $z;
       Char >= $0, Char =< $9;
       Char =:= $-; Char =:= $_;
       Char =:= $.; Char =:= $~ ->
    url_encode(String, [Char|Accum]);
url_encode([Char|String], Accum)
  when Char >=0, Char =< 255 ->
    url_encode(String, [hex_char(Char rem 16), hex_char(Char div 16),$%|Accum]).

extract_metadata(Headers) ->
    [{Key, Value} || {["x-amz-meta-"|Key], Value} <- Headers].
