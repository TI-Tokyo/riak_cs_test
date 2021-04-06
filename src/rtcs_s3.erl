%% riak_test in riak_cs-2.1 used an old, forked version of erlcloud,
%% with erlcloud_s3:s3_request/9 customized and made exportable. That
%% version, https://github.com/basho/erlcloud/releases/tag/0.4.6,
%% could not be (easily) built in otp-22, so here's some functions
%% manually copied from it.

-module(rtcs_s3).

-export([new/2, new/3, new/4, new/5, new/8,
         s3_request/9, get_object/3, put_object/4,
         create_bucket/2,
         upgrade_config/1]).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").
-include("rtcs_erlcloud_aws.hrl").

-define(XMLNS_S3, "http://s3.amazonaws.com/doc/2006-03-01/").


-type s3_bucket_acl() :: private
                       | public_read
                       | public_read_write
                       | authenticated_read
                       | bucket_owner_read
                       | bucket_owner_full_control.

-type s3_location_constraint() :: none
                                | us_west_1
                                | eu.


-spec new(string(), string()) -> rtcs_aws_config().
new(AccessKeyID, SecretAccessKey) ->
    #rtcs_aws_config{
     access_key_id=AccessKeyID,
     secret_access_key=SecretAccessKey
    }.

-spec new(string(), string(), string()) -> rtcs_aws_config().
new(AccessKeyID, SecretAccessKey, Host) ->
    #rtcs_aws_config{
     access_key_id=AccessKeyID,
     secret_access_key=SecretAccessKey,
     s3_host=Host
    }.


-spec new(string(), string(), string(), non_neg_integer()) -> rtcs_aws_config().
new(AccessKeyID, SecretAccessKey, Host, Port) ->
    #rtcs_aws_config{
     access_key_id=AccessKeyID,
     secret_access_key=SecretAccessKey,
     s3_host=Host,
     s3_port=Port
    }.

-spec new(string(), string(), string(), non_neg_integer(), string()) -> rtcs_aws_config().
new(AccessKeyID, SecretAccessKey, Host, Port, Protocol) ->
    #rtcs_aws_config{
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
          proplists:proplist()) -> rtcs_aws_config().
new(AccessKeyID, SecretAccessKey, Host, Port, Protocol, ProxyHost, ProxyPort,
    HttpOptions) ->
    #rtcs_aws_config{
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
    RequestHeaders = [{"date", Date}, {"authorization", Authorization} | FHeaders] ++
        case ContentMD5 of
            "" -> [];
            _ -> [{"content-md5", binary_to_list(ContentMD5)}]
        end,
    RequestURI = lists:flatten([
                                Config#rtcs_aws_config.s3_prot,
                                "://",
                                case Host of "" -> ""; _ -> [Host, $.] end,
                                Config#rtcs_aws_config.s3_host, port_spec(Config),
                                EscapedPath,
                                format_subresources(Subresources),
                                if
                                    Params =:= [] -> "";
                                    Subresources =:= [] -> [$?, make_query_string(Params)];
                                    true -> [$&, make_query_string(Params)]
                                end
                               ]),
    Timeout = 240000,
    Options = Config#rtcs_aws_config.http_options,
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


s3_simple_request(Config, Method, Host, Path, Subresource, Params, POSTData, Headers) ->
    case s3_request(Config, Method, Host, Path, Subresource, Params, POSTData, Headers, []) of
        {_Headers, ""} -> ok;
        {_Headers, Body} ->
            XML = element(1,xmerl_scan:string(Body)),
            case XML of
                #xmlElement{name='Error'} ->
                    ErrCode = rtcs_s3_xml:get_text("/Error/Code", XML),
                    ErrMsg = rtcs_s3_xml:get_text("/Error/Message", XML),
                    erlang:error({s3_error, ErrCode, ErrMsg});
                _ ->
                    ok
            end
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
    Signature = base64:encode(crypto:hmac(sha, Config#rtcs_aws_config.secret_access_key, StringToSign)),
    ["AWS ", Config#rtcs_aws_config.access_key_id, $:, Signature].

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

port_spec(#rtcs_aws_config{s3_port=80}) ->
    "";
port_spec(#rtcs_aws_config{s3_port=Port}) ->
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



-spec get_object(string(), string(), proplists:proplist() | rtcs_aws_config()) -> proplists:proplist().
get_object(BucketName, Key, Config)
  when is_record(Config, rtcs_aws_config) ->
    get_object(BucketName, Key, [], Config).

-spec get_object(string(), string(), proplists:proplist(), rtcs_aws_config()) -> proplists:proplist().
get_object(BucketName, Key, Options, Config) ->
    fetch_object(get, BucketName, Key, Options, Config).

-spec fetch_object(atom(), string(), string(), proplists:proplist(), rtcs_aws_config()) -> proplists:proplist().
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


-spec put_object(string(), string(), iolist(), rtcs_aws_config()) -> proplists:proplist().
put_object(BucketName, Key, Value, #rtcs_aws_config{} = Config) ->
    put_object(BucketName, Key, Value, [], Config).

-spec put_object(string(), string(), iolist(), proplists:proplist(), [{string(), string()}] | rtcs_aws_config()) -> {proplists:proplist(), proplists:proplist()}.
put_object(BucketName, Key, Value, Options, Config)
  when is_record(Config, rtcs_aws_config) ->
    put_object(BucketName, Key, Value, Options, [], Config).

-spec put_object(string(), string(), iolist(), proplists:proplist(), [{string(), string()}], rtcs_aws_config()) -> {proplists:proplist(), proplists:proplist()}.
put_object(BucketName, Key, Value, Options, HTTPHeaders0, Config)
  when is_list(BucketName), is_list(Key), is_list(Value) orelse is_binary(Value),
       is_list(Options) ->
    {ContentType, HTTPHeaders} = case lists:keytake("Content-Type", 1, HTTPHeaders0) of
                                     {value, {_, CType}, Rest} -> {CType, Rest};
                                     false -> {"application/octet-stream", HTTPHeaders0}
                                 end,
    RequestHeaders = [{"x-amz-acl", encode_acl(proplists:get_value(acl, Options))}|HTTPHeaders]
        ++ [{"x-amz-meta-" ++ string:to_lower(MKey), MValue} ||
               {MKey, MValue} <- proplists:get_value(meta, Options, [])],
    ReturnResponse = proplists:get_value(return_response, Options, false),
    POSTData = {iolist_to_binary(Value), ContentType},
    {Headers, Body} = s3_request(Config, put, BucketName, [$/|Key], [], [],
                                 POSTData, RequestHeaders, []),
    case ReturnResponse of
        true ->
            {Headers, Body};
        false ->
            [{version_id, proplists:get_value("x-amz-version-id", Headers, "null")}]
    end.




-spec create_bucket(string(), rtcs_aws_config()) -> ok.
create_bucket(BucketName, #rtcs_aws_config{} = Config) ->
    create_bucket(BucketName, private, Config).

-spec create_bucket(string(), s3_bucket_acl(), rtcs_aws_config()) -> ok.
create_bucket(BucketName, ACL, #rtcs_aws_config{} = Config) ->
    create_bucket(BucketName, ACL, none, Config).

-spec create_bucket(string(), s3_bucket_acl(), s3_location_constraint(), rtcs_aws_config()) -> ok.
create_bucket(BucketName, ACL, LocationConstraint, Config)
  when is_list(BucketName), is_atom(ACL), is_atom(LocationConstraint) ->
    Headers = case ACL of
                  private -> [];  %% private is the default
                  _       -> [{"x-amz-acl", encode_acl(ACL)}]
              end,
    POSTData = case LocationConstraint of
                   none -> {<<>>, "application/octet-stream"};
                   Location when Location =:= eu; Location =:= us_west_1 ->
                       LocationName = case Location of eu -> "EU"; us_west_1 -> "us-west-1" end,
                       XML = {'CreateBucketConfiguration', [{xmlns, ?XMLNS_S3}],
                              [{'LocationConstraint', [LocationName]}]},
                       list_to_binary(xmerl:export_simple([XML], xmerl_xml))
               end,
    s3_simple_request(Config, put, BucketName, "/", "", [], POSTData, Headers).


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


encode_acl(undefined)                 -> undefined;
encode_acl(private)                   -> "private";
encode_acl(public_read)               -> "public-read";
encode_acl(public_read_write)         -> "public-read-write";
encode_acl(authenticated_read)        -> "authenticated-read";
encode_acl(bucket_owner_read)         -> "bucket-owner-read";
encode_acl(bucket_owner_full_control) -> "bucket-owner-full-control".

-spec upgrade_config(rtcs_aws_config()) -> erlcloud:aws_config().
upgrade_config(#rtcs_aws_config{access_key_id = KeyId,
                                secret_access_key = SAK}) ->
    #aws_config{access_key_id = KeyId,
                secret_access_key = SAK}.
