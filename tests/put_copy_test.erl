%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2014 Basho Technologies, Inc.  All Rights Reserved.
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
-module(put_copy_test).

-export([confirm/0]).
-include_lib("eunit/include/eunit.hrl").

-include_lib("erlcloud/include/erlcloud_aws.hrl").

-define(assert403(X),
        ?assertError({aws_error, {http_error, 403, _, _}}, (X))).
-define(assertProp(Key, Expected, Props),
        ?assertEqual(Expected,
                     proplists:get_value(Key, Props))).

-define(BUCKET, "put-copy-bucket-test").
-define(KEY, "pocket").

-define(DATA0, <<"pocket">>).

-define(BUCKET2, "put-target-bucket").
-define(KEY2, "sidepocket").
-define(KEY3, "superpocket").
-define(BUCKET3, "the-other-put-target-bucket").
-define(BUCKET4, "no-cl-bucket").
-define(SRC_KEY, "source").
-define(TGT_KEY, "target").
-define(MP_TGT_KEY, "mp-target").
-define(REPLACE_KEY, "replace-target").

confirm() ->
    %% ibrowse
    application:ensure_all_started(ibrowse),

    {{UserConfig, _}, {RiakNodes, _CSNodes}} = rtcs:setup(1),
    ?assertEqual(ok, erlcloud_s3:create_bucket(?BUCKET, UserConfig)),
    Data = ?DATA0,
    ?assertMatch([{version_id, "null"}|_],
                 erlcloud_s3:put_object(?BUCKET, ?KEY, Data, UserConfig)),
    ?assertMatch([{version_id, "null"}|_],
                 erlcloud_s3:put_object(?BUCKET, ?KEY2, Data, UserConfig)),

    RiakNode = hd(RiakNodes),
    UserConfig2 = rtcs_admin:create_user(RiakNode, 1),
    UserConfig3 = rtcs_admin:create_user(RiakNode, 1),

    ?assertEqual(ok, erlcloud_s3:create_bucket(?BUCKET2, UserConfig)),
    ?assertEqual(ok, erlcloud_s3:create_bucket(?BUCKET3, UserConfig2)),

    ok = verify_simple_copy(UserConfig),
    ok = verify_others_copy(UserConfig, UserConfig2),
    ok = verify_multipart_copy(UserConfig),
    ok = verify_security(UserConfig, UserConfig2, UserConfig3),
    ok = verify_source_not_found(UserConfig),
    ok = verify_replace_usermeta(UserConfig),
    ok = verify_without_cl_header(UserConfig),

    ?assertEqual([{delete_marker, false}, {version_id, "null"}],
                 erlcloud_s3:delete_object(?BUCKET, ?KEY, UserConfig)),
    ?assertEqual([{delete_marker, false}, {version_id, "null"}],
                 erlcloud_s3:delete_object(?BUCKET, ?KEY2, UserConfig)),
    ?assertEqual([{delete_marker, false}, {version_id, "null"}],
                 erlcloud_s3:delete_object(?BUCKET2, ?KEY2, UserConfig)),
    ?assertEqual([{delete_marker, false}, {version_id, "null"}],
                 erlcloud_s3:delete_object(?BUCKET3, ?KEY, UserConfig2)),

    pass.


verify_simple_copy(UserConfig) ->

    ?assertEqual([{copy_source_version_id, "false"}, {version_id, "null"}],
                 erlcloud_s3:copy_object(?BUCKET2, ?KEY2, ?BUCKET, ?KEY, UserConfig)),

    Props = erlcloud_s3:get_object(?BUCKET2, ?KEY2, UserConfig),
    logger:debug("copied object: ~p", [Props]),
    ?assertEqual(?DATA0, proplists:get_value(content, Props)),

    ok.


verify_others_copy(UserConfig, OtherUserConfig) ->
    %% try copy to fail, because no permission
    ?assert403(erlcloud_s3:copy_object(?BUCKET3, ?KEY, ?BUCKET, ?KEY, OtherUserConfig)),

    %% set key public
    Acl = [{acl, public_read}],
    ?assertMatch([{version_id,"null"}|_],
                 erlcloud_s3:put_object(?BUCKET, ?KEY, ?DATA0,
                                        Acl, [], UserConfig)),

    %% make sure observable from Other
    Props = erlcloud_s3:get_object(?BUCKET, ?KEY, OtherUserConfig),
    ?assertEqual(?DATA0, proplists:get_value(content, Props)),

    %% try copy
    ?assertEqual([{copy_source_version_id, "false"}, {version_id, "null"}],
                 erlcloud_s3:copy_object(?BUCKET3, ?KEY, ?BUCKET, ?KEY, OtherUserConfig)),

    Props2 = erlcloud_s3:get_object(?BUCKET3, ?KEY, OtherUserConfig),
    logger:debug("copied object: ~p", [Props2]),
    ?assertEqual(?DATA0, proplists:get_value(content, Props2)),
    ok.

verify_multipart_copy(_UserConfig) ->
    %% erlcloud-3.6.7 does not have mutipart copy methods (even though
    %% 0.4.7 had them), so we skip these tests here. This
    %% functionality is covered in boto_tests (see
    %% SimpleCopyTest.test_put_copy_object_from_mp)
    ok.

verify_security(Alice, Bob, Charlie) ->
    AlicesBucket = "alice",
    AlicesPublicBucket = "alice-public",
    AlicesObject = "alices-secret-note",
    AlicesPublicObject = "alices-public-note",

    BobsBucket = "bob",
    BobsObject = "bobs-secret-note",

    CharliesBucket = "charlie",

    %% setup Alice's data
    ?assertEqual(ok, erlcloud_s3:create_bucket(AlicesBucket, Alice)),
    ?assertEqual(ok, erlcloud_s3:create_bucket(AlicesPublicBucket, public_read_write, Alice)),

    ?assertMatch([{version_id, "null"}|_],
                 erlcloud_s3:put_object(AlicesBucket, AlicesObject,
                                        <<"I'm here!!">>, Alice)),
    ?assertMatch([{version_id, "null"}|_],
                 erlcloud_s3:put_object(AlicesBucket, AlicesPublicObject,
                                        <<"deadbeef">>, [{acl, public_read}], Alice)),
    ?assertMatch([{version_id, "null"}|_],
                 erlcloud_s3:put_object(AlicesPublicBucket, AlicesObject,
                                        <<"deadly public beef">>, Alice)),

    %% setup Bob's box
    ?assertEqual(ok, erlcloud_s3:create_bucket(BobsBucket, Bob)),
    ?assertMatch([{version_id, "null"}|_],
                 erlcloud_s3:put_object(BobsBucket, BobsObject,
                                        <<"bobfat">>, Bob)),

    %% >> setup Charlie's box
    ?assertEqual(ok, erlcloud_s3:create_bucket(CharliesBucket, Charlie)),

    %% >> Bob can do it right
    %% Bring Alice's objects to Bob's bucket
    ?assert403(erlcloud_s3:copy_object(BobsBucket, AlicesObject,
                                       AlicesBucket, AlicesObject, Bob)),

    ?assertEqual([{copy_source_version_id, "false"}, {version_id, "null"}],
                 erlcloud_s3:copy_object(BobsBucket, AlicesPublicObject,
                                         AlicesBucket, AlicesPublicObject, Bob)),

    %% TODO: put to public bucket is degrated for now
    %% ?assertEqual([{copy_source_version_id, "false"}, {version_id, "null"}],
    %%              erlcloud_s3:copy_object(BobsBucket, AlicesObject,
    %%                AlicesPublicBucket, AlicesObject, Bob)),

    %% Bring Bob's object to Alice's bucket
    ?assertEqual([{copy_source_version_id, "false"}, {version_id, "null"}],
                 erlcloud_s3:copy_object(AlicesPublicBucket, BobsObject,
                                     BobsBucket, BobsObject, Bob)),
    %% Cleanup Bob's
    ?assertEqual([{delete_marker, false}, {version_id, "null"}],
                 erlcloud_s3:delete_object(BobsBucket, AlicesPublicObject, Bob)),
    ?assertEqual([{delete_marker, false}, {version_id, "null"}],
                 erlcloud_s3:delete_object(BobsBucket, AlicesObject, Bob)),
    %% ?assertEqual([{delete_marker, false}, {version_id, "null"}],
    %%              erlcloud_s3:delete_object(AlicesPublicObject, BobsObject, Bob)),

    %% >> Charlie can't do it
    %% try copying Alice's private object to Charlie's
    ?assert403(erlcloud_s3:copy_object(CharliesBucket, AlicesObject,
                                       AlicesBucket, AlicesObject, Charlie)),

    ?assert403(erlcloud_s3:copy_object(AlicesPublicBucket, AlicesObject,
                                       AlicesBucket, AlicesObject, Charlie)),

    %% try copy Alice's public object to Bob's
    ?assert403(erlcloud_s3:copy_object(BobsBucket, AlicesPublicObject,
                                       AlicesBucket, AlicesPublicObject, Charlie)),
    ?assert403(erlcloud_s3:copy_object(BobsBucket, AlicesObject,
                                       AlicesPublicBucket, AlicesObject, Charlie)),

    %% charlie tries to copy anonymously, which should fail in 403
    CSPort = Charlie#aws_config.s3_port,
    URL = lists:flatten(io_lib:format("http://~s.~s:~p/~s",
                                      [AlicesPublicBucket, Charlie#aws_config.s3_host,
                                       CSPort, AlicesObject])),
    Headers = [{"x-amz-copy-source", string:join([AlicesBucket, AlicesObject], "/")},
               {"Content-Length", 0}],
    #hackney_client_options{proxy = {ProxyHost, ProxyPort}} =
        Charlie#aws_config.hackney_client_options,
    {ok, Status, Hdr, _Msg} =
        ibrowse:send_req(URL, Headers, put, [], [{proxy_host, ProxyHost},
                                                 {proxy_port, ProxyPort}]),
    logger:debug("request ~p ~p => ~p ~p", [URL, Headers, Status, Hdr]),
    ?assertEqual("403", Status),

    ok.

verify_source_not_found(UserConfig) ->
    NonExistingKey = "non-existent-source",
    {'EXIT', {{aws_error, {http_error, 404, _, ErrorXml}}, _Stack}} =
        (catch erlcloud_s3:copy_object(?BUCKET2, ?KEY2,
                                       ?BUCKET, NonExistingKey, UserConfig)),
    logger:debug("ErrorXml: ~s", [ErrorXml]),
    ?assert(string:str(
              binary_to_list(ErrorXml),
              "<Resource>/" ++ ?BUCKET ++ "/" ++ NonExistingKey ++ "</Resource>")
            > 0).

verify_replace_usermeta(_UserConfig) ->
    %% it appears in erlcloud-3.6.7, erlcloud_s3:copy_object/6 ignores
    %% metadata_directive; scrapping this test as well.  See
    %% boto_test_metadata.ObjectMetadataTest.test_mp_object_metadata,
    %% which covers this case.
    ok.


%% Verify reuqests without Content-Length header, they should succeed.
%% To avoid automatic Content-Length header addition by HTTP client library,
%% this test uses `curl' command line utitlity, intended.
verify_without_cl_header(UserConfig) ->
    ?assertEqual(ok, erlcloud_s3:create_bucket(?BUCKET4, UserConfig)),
    Data = ?DATA0,
    ?assertMatch([{version_id, "null"}|_],
                 erlcloud_s3:put_object(?BUCKET4, ?SRC_KEY, Data, UserConfig)),
    verify_without_cl_header(UserConfig, normal, Data),
    verify_without_cl_header(UserConfig, mp, Data),
    ok.

verify_without_cl_header(UserConfig, normal, Data) ->
    logger:info("Verify basic (non-MP) PUT copy without Content-Length header"),
    Target = fmt("/~s/~s", [?BUCKET4, ?TGT_KEY]),
    Source = fmt("/~s/~s", [?BUCKET4, ?SRC_KEY]),
    _Res = exec_curl(UserConfig, "PUT", Target, [{"x-amz-copy-source", Source}]),

    Props = erlcloud_s3:get_object(?BUCKET4, ?TGT_KEY, UserConfig),
    ?assertEqual(Data, proplists:get_value(content, Props)),
    ok;
verify_without_cl_header(UserConfig, mp, Data) ->
    logger:info("Verify Multipart upload copy without Content-Length header"),
    {ok, InitUploadRes} = erlcloud_s3:start_multipart(
                            ?BUCKET4, ?MP_TGT_KEY, [{"Content-Type", "application/octet-stream"}],
                            [], UserConfig),
    UploadId = proplists:get_value(uploadId, InitUploadRes),
    logger:info("~p ~p", [InitUploadRes, UploadId]),
    Source = fmt("/~s/~s", [?BUCKET4, ?SRC_KEY]),
    MpTarget = fmt("/~s/~s?partNumber=1&uploadId=~s", [?BUCKET4, ?MP_TGT_KEY, UploadId]),
    _Res = exec_curl(UserConfig, "PUT", MpTarget,
                     [{"x-amz-copy-source", Source},
                      {"x-amz-copy-source-range", "bytes=1-2"}]),

    ListPartsXml = erlcloud_s3_multipart:list_parts(?BUCKET4, ?MP_TGT_KEY, UploadId, [], UserConfig),
    logger:debug("ListParts: ~p", [ListPartsXml]),
    ListPartsRes = erlcloud_s3_multipart:parts_to_term(ListPartsXml),
    Parts = proplists:get_value(parts, ListPartsRes),
    EtagList = [{PartNum, Etag} || {PartNum, [{etag, Etag}, {size, _Size}]} <- Parts],
    logger:debug("EtagList: ~p", [EtagList]),
    ?assertEqual(ok, erlcloud_s3_multipart:complete_upload(
                       ?BUCKET4, ?MP_TGT_KEY, UploadId, EtagList, UserConfig)),
    Props = erlcloud_s3:get_object(?BUCKET4, ?MP_TGT_KEY, UserConfig),
    ExpectedBody = binary:part(Data, 1, 2),
    ?assertEqual(ExpectedBody, proplists:get_value(content, Props)),
    ok.

exec_curl(#aws_config{hackney_client_options = #hackney_client_options{proxy = {_, Port}}} = UserConfig,
          Method, Resource, AmzHeaders) ->
    ContentType = "application/octet-stream",
    Date = httpd_util:rfc1123_date(),
    Auth = rtcs_admin:make_authorization(
             Method, Resource, ContentType, UserConfig, Date, AmzHeaders),
    HeaderArgs = [fmt("-H '~s: ~s' ", [K, V]) ||
                     {K, V} <- [{"Date", Date}, {"Authorization", Auth},
                                {"Content-Type", ContentType} | AmzHeaders]],
    Cmd="curl -X " ++ Method ++ " -v -s " ++ HeaderArgs ++
        "'http://127.0.0.1:" ++ integer_to_list(Port) ++ Resource ++ "'",
    logger:debug("Curl command line: ~s", [Cmd]),
    Res = os:cmd(Cmd),
    logger:debug("Curl result: ~s", [Res]),
    Res.

fmt(Fmt, Args) ->
    lists:flatten(io_lib:format(Fmt, Args)).
