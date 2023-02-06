%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2013 Basho Technologies, Inc.  All Rights Reserved.
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

-module(object_get_test).

%% @doc `riak_test' module for testing object get behavior.

-export([confirm/0]).
-include("rtcs.hrl").
-include_lib("xmerl/include/xmerl.hrl").

%% keys for non-multipart objects
-define(TEST_BUCKET,        "riak-test-bucket").
-define(KEY_SINGLE_BLOCK,   "riak_test_key1").
-define(KEY_MULTIPLE_BLOCK, "riak_test_key2").

%% keys for multipart uploaded objects
-define(KEY_MP_TINY,        "riak_test_mp_tiny").  % single part, single block
-define(KEY_MP_SMALL,       "riak_test_mp_small"). % single part, multiple blocks
-define(KEY_MP_LARGE,       "riak_test_mp_large"). % multiple parts


confirm() ->
    {{UserConfig, _}, {_RiakNodes, _CSNodes}} = rtcs_dev:setup(1),

    logger:info("User is valid on the cluster, and has no buckets"),
    ?assertNoBuckets(UserConfig),

    logger:info("creating bucket ~p", [?TEST_BUCKET]),
    ?assertEqual(ok, erlcloud_s3:create_bucket(?TEST_BUCKET, UserConfig)),

    ?assertHasBucket(?TEST_BUCKET, UserConfig),

    non_mp_get_cases(UserConfig),
    mp_get_cases(UserConfig),
    timestamp_skew_cases(UserConfig),
    long_key_cases(UserConfig),
    pass.

non_mp_get_cases(UserConfig) ->
    %% setup objects
    SingleBlock = crypto:strong_rand_bytes(400),
    erlcloud_s3:put_object(?TEST_BUCKET, ?KEY_SINGLE_BLOCK, SingleBlock, UserConfig),
    MultipleBlock = crypto:strong_rand_bytes(4000000), % not aligned to block boundary
    erlcloud_s3:put_object(?TEST_BUCKET, ?KEY_MULTIPLE_BLOCK, MultipleBlock, UserConfig),

    %% basic GET test cases
    basic_get_test_case(?TEST_BUCKET, ?KEY_SINGLE_BLOCK, SingleBlock, UserConfig),
    basic_get_test_case(?TEST_BUCKET, ?KEY_MULTIPLE_BLOCK, MultipleBlock, UserConfig),

    %% GET after nval=1 GET failure
    rt_intercept:add(rtcs_dev:cs_node(1), {riak_cs_block_server, [{{get_block_local, 6}, get_block_local_insufficient_vnode_at_nval1}]}),
    Res = erlcloud_s3:get_object(?TEST_BUCKET, ?KEY_SINGLE_BLOCK, UserConfig),
    ?assertEqual(SingleBlock, proplists:get_value(content, Res)),
    rt_intercept:clean(rtcs_dev:cs_node(1), riak_cs_block_server),

    %% Range GET for single-block object test cases
    [range_get_test_case(?TEST_BUCKET, ?KEY_SINGLE_BLOCK, SingleBlock,
                         Range, UserConfig)
     || Range <- [{10, 20},
                  {0, none}, {none, 10},
                  {0, 0}, {0, 99}, {0, 1000000}]],

    %% Range GET for multiple-block object test cases
    [range_get_test_case(?TEST_BUCKET, ?KEY_MULTIPLE_BLOCK, MultipleBlock,
                         {0, End}, UserConfig)
     || End <- [mb(1)-2, mb(1)-1, mb(1), mb(1)+1]],
    [range_get_test_case(?TEST_BUCKET, ?KEY_MULTIPLE_BLOCK, MultipleBlock,
                         {Start, mb(2)}, UserConfig)
     || Start <- [mb(1)-2, mb(1)-1, mb(1), mb(1)+1]],
    range_get_test_case(?TEST_BUCKET, ?KEY_MULTIPLE_BLOCK, MultipleBlock,
                        {100, mb(3)}, UserConfig),
    range_get_test_case(?TEST_BUCKET, ?KEY_MULTIPLE_BLOCK, MultipleBlock,
                        {0, none}, UserConfig),

    %% Multiple ranges, CS returns whole resources.
    multiple_range_get_test_case(?TEST_BUCKET, ?KEY_MULTIPLE_BLOCK, MultipleBlock,
                                 [{10, 20}, {30, 50}], UserConfig),
    multiple_range_get_test_case(?TEST_BUCKET, ?KEY_MULTIPLE_BLOCK, MultipleBlock,
                                 [{10, 50}, {20, 50}], UserConfig),

    %% Invalid ranges
    LastPosExceeded = byte_size(MultipleBlock),
    invalid_range_get_test_case(?TEST_BUCKET, ?KEY_MULTIPLE_BLOCK, MultipleBlock,
                                [{LastPosExceeded, LastPosExceeded + 10}], UserConfig),
    invalid_range_get_test_case(?TEST_BUCKET, ?KEY_MULTIPLE_BLOCK, MultipleBlock,
                                [{20, 10}], UserConfig),
    ok.

mp_get_cases(UserConfig) ->
    TinyContent = multipart_upload(?TEST_BUCKET, ?KEY_MP_TINY,
                                   [400], UserConfig),
    SmallContent = multipart_upload(?TEST_BUCKET, ?KEY_MP_SMALL,
                                    [mb(3)], UserConfig),
    LargeContent = multipart_upload(?TEST_BUCKET, ?KEY_MP_LARGE,
                                    [mb(10), mb(5), mb(9) + 123, mb(6), 400], % 30MB + 523 B
                                    UserConfig),

    %% Range GET for single part / single block
    [range_get_test_case(?TEST_BUCKET, ?KEY_MP_TINY, TinyContent,
                         Range, UserConfig)
     || Range <- [{10, 20},
                  {0, none}, {none, 10},
                  {0, 0}, {0, 99}, {0, 1000000}]],

    %% Range GET for single part / multiple blocks
    [range_get_test_case(?TEST_BUCKET, ?KEY_MP_SMALL, SmallContent,
                         {Start, End}, UserConfig)
     || Start <- [100, mb(1)+100],
        End   <- [mb(1)+100, mb(3)-1, mb(4)]],

    %% Range GET for multiple parts / multiple blocks
    [range_get_test_case(?TEST_BUCKET, ?KEY_MP_LARGE, LargeContent,
                         {Start, End}, UserConfig)
     || Start <- [mb(1), mb(16)],
        End   <- [mb(16), mb(30), mb(30) + 500, mb(1000)]],
    ok.

timestamp_skew_cases(UserConfig) ->
    BucketName = "timestamp-skew-cases",
    KeyName = "timestamp-skew-cases",
    Data = <<"bark! bark! bark!!!">>,
    ?assertEqual(ok, erlcloud_s3:create_bucket(BucketName, UserConfig)),
    erlcloud_s3:put_object(BucketName, KeyName, Data, UserConfig),

    meck:new(httpd_util, [passthrough]),
    %% To emulate clock skew, override erlang:localtime/0 to
    %% enable random walk time, as long as erlcloud_s3 uses
    %% httpd_util:rfc1123_date/1 for generating timestamp of
    %% HTTP request header.
    %% `Date = httpd_util:rfc1123_date(erlang:localtime()),`
    meck:expect(httpd_util, rfc1123_date,
                fun(Localtime) ->
                        Seconds = calendar:datetime_to_gregorian_seconds(Localtime),
                        SkewedTime = calendar:gregorian_seconds_to_datetime(Seconds - 987),
                        Date = meck:passthrough([SkewedTime]),
                        logger:info("Clock skew: ~p => ~p => ~p", [Localtime, SkewedTime, Date]),
                        Date
                end),
    try
        erlcloud_s3:get_object(BucketName, KeyName, UserConfig)
    catch
        error:{aws_error, {http_error, 403, _, Body0}} ->
            Body = unicode:characters_to_list(Body0),
            #xmlElement{name = 'Error'} = XML = element(1,xmerl_scan:string(Body)),
            ?assertEqual("RequestTimeTooSkewed", erlcloud_xml:get_text("/Error/Code", XML)),
            ErrMsg = "The difference between the request time and the current time is too large.",
            ?assertEqual(ErrMsg, erlcloud_xml:get_text("/Error/Message", XML));
        E:R ->
            logger:error("~p:~p", [E, R]),
            ?assert(false)
    after
        meck:unload(httpd_util)
    end.

long_key_cases(UserConfig) ->
    LongKey = binary_to_list(binary:copy(<<"a">>, 1024)),
    TooLongKey = binary_to_list(binary:copy(<<"b">>, 1025)),
    Data = <<"pocketburger">>,
    ?assertProp(version_id, "null", erlcloud_s3:put_object(?TEST_BUCKET, LongKey, Data, UserConfig)),
    ErrorString = <<"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error>"
                    "<Code>KeyTooLongError</Code><Message>Your key is too long</Message><Size>1025</Size>"
                    "<MaxSizeAllowed>1024</MaxSizeAllowed><RequestId></RequestId></Error>">>,
    ?assertError({aws_error, {http_error, 400, _, ErrorString}},
                 erlcloud_s3:put_object(?TEST_BUCKET, TooLongKey, Data, UserConfig)).

mb(MegaBytes) ->
    MegaBytes * 1024 * 1024.

basic_get_test_case(Bucket, Key, ExpectedContent, Config) ->
    Obj = erlcloud_s3:get_object(Bucket, Key, Config),
    assert_whole_content(ExpectedContent, Obj).

assert_whole_content(ExpectedContent, ResultObj) ->
    Content = proplists:get_value(content, ResultObj),
    ContentLength = proplists:get_value(content_length, ResultObj),
    ?assertEqual(byte_size(ExpectedContent), list_to_integer(ContentLength)),
    ?assertEqual(byte_size(ExpectedContent), byte_size(Content)),
    ?assertEqual(ExpectedContent, Content).

range_get_test_case(Bucket, Key, WholeContent, {Start, End}, Config) ->
    Range = format_ranges([{Start, End}]),
    Obj = erlcloud_s3:get_object(Bucket, Key, [{range, Range}], Config),
    Content = proplists:get_value(content, Obj),
    ContentLength = proplists:get_value(content_length, Obj),
    WholeSize = byte_size(WholeContent),
    {Skip, Length} = range_skip_length({Start, End}, WholeSize),
    ?assertEqual(Length, list_to_integer(ContentLength)),
    ?assertEqual(Length, byte_size(Content)),
    %% no content_range in erlcloud_s3:get_object result:
    %% just check that the contents data returned are good
    ExpectedContent = binary:part(WholeContent, Skip, Length),
    ?assertEqual(ExpectedContent, Content).

multiple_range_get_test_case(Bucket, Key, WholeContent, Ranges, Config) ->
    RangeValue = format_ranges(Ranges),
    Obj = erlcloud_s3:get_object(Bucket, Key, [{range, RangeValue}], Config),
    assert_whole_content(WholeContent, Obj).

invalid_range_get_test_case(Bucket, Key, _WholeContent, Ranges, Config) ->
    RangeValue = format_ranges(Ranges),
    {'EXIT', {{aws_error, {http_error, 416, _, Body}}, _Backtrace}} =
        (catch erlcloud_s3:get_object(Bucket, Key, [{range, RangeValue}], Config)),
    ?assertMatch({match, _},
                 re:run(Body, "InvalidRange", [multiline])).

format_ranges(Ranges) ->
    Formatted = [format_range(Range) || Range <- Ranges],
    io_lib:format("bytes=~s", [string:join(Formatted, ",")]).

format_range(Range) ->
    RangeStr = case Range of
                   {none, End} ->
                       io_lib:format("-~B", [End]);
                   {Start, none} ->
                       io_lib:format("~B-", [Start]);
                   {Start, End} ->
                       io_lib:format("~B-~B", [Start, End])
               end,
    lists:flatten(RangeStr).

%% TODO: riak_test includes its own mochiweb by escriptizing.
%% End position which is larger than size is fixed on the branch 1.5 of basho/mochweb:
%%   https://github.com/basho/mochiweb/commit/38992be7822ddc1b8e6f318ba8e73fc8c0b7fd22
%%   Accept range end position which exceededs the resource size
%% After mochiweb is tagged, change riakhttpc and webmachine's deps to the tag.
%% So this function should be removed and replaced by mochiweb_http:range_skip_length/2.
range_skip_length(Spec, Size) ->
    case Spec of
        {Start, End} when is_integer(Start), is_integer(End),
                          0 =< Start, Start < Size, Size =< End ->
            {Start, Size - Start};
        _ ->
            mochiweb_http:range_skip_length(Spec, Size)
    end.

multipart_upload(Bucket, Key, Sizes, Config) ->
    {ok, InitRes} = erlcloud_s3:start_multipart(
                      Bucket, Key, [], [], Config),
    UploadId = proplists:get_value(uploadId, InitRes),
    Content = upload_parts(Bucket, Key, UploadId, Config, 1, Sizes, [], []),
    basic_get_test_case(Bucket, Key, Content, Config),
    Content.

upload_parts(Bucket, Key, UploadId, Config, _PartCount, [], Contents, Parts) ->
    ?assertEqual(ok, erlcloud_s3:complete_multipart(
                       Bucket, Key, UploadId, lists:reverse(Parts), [], Config)),
    iolist_to_binary(lists:reverse(Contents));
upload_parts(Bucket, Key, UploadId, Config, PartCount, [Size | Sizes], Contents, Parts) ->
    Content = crypto:strong_rand_bytes(Size),
    {ok, UploadRes} = erlcloud_s3:upload_part(
                        Bucket, Key, UploadId, PartCount, Content, [], Config),
    PartEtag = proplists:get_value(etag, UploadRes),
    upload_parts(Bucket, Key, UploadId, Config, PartCount + 1,
                 Sizes, [Content | Contents], [{PartCount, PartEtag} | Parts]).
