%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2013 Basho Technologies, Inc.  All Rights Reserved.
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

-module(rtcs_multipart).

-export([multipart_upload/4,
         upload_and_assert_part/6,
 upload_id_present/2
        ]).

-include_lib("eunit/include/eunit.hrl").

%% Upload object by multipart and return generetad (=expected) content
multipart_upload(Bucket, Key, Sizes, Config) ->
    {ok, InitRes} = erlcloud_s3:start_multipart(
                      Bucket, Key, [], [], Config),
    UploadId = proplists:get_value(uploadId, InitRes),
    Content = upload_parts(Bucket, Key, UploadId, Config, 1, Sizes, [], []),
    Content.

upload_parts(Bucket, Key, UploadId, Config, _PartCount, [], Contents, Parts) ->
    ?assertEqual(ok, erlcloud_s3:complete_multipart(
                       Bucket, Key, UploadId, lists:reverse(Parts), [], Config)),
    iolist_to_binary(lists:reverse(Contents));
upload_parts(Bucket, Key, UploadId, Config, PartCount, [Size | Sizes], Contents, Parts) ->
    Content = crypto:strong_rand_bytes(Size),
    {ok, Res} = erlcloud_s3:upload_part(
                  Bucket, Key, UploadId, PartCount, Content, [], Config),
    PartEtag = proplists:get_value(etag, Res),
    upload_parts(Bucket, Key, UploadId, Config, PartCount + 1,
                 Sizes, [Content | Contents], [{PartCount, PartEtag} | Parts]).


upload_and_assert_part(Bucket, Key, UploadId, PartNum, PartData, Config) ->
    {ok, UploadRes} = erlcloud_s3:upload_part(Bucket, Key, UploadId, PartNum, PartData, [], Config),
    assert_part(Bucket, Key, UploadId, Config, UploadRes).


assert_part(Bucket, _Key, UploadId, Config, UploadRes) ->
    ETag = proplists:get_value(etag, UploadRes),
    {ok, MPU} = erlcloud_s3:list_multipart_uploads(Bucket, [], [], Config),
    Uploads = proplists:get_value(uploads, MPU),
    ?assert(lists:any(fun(P) -> proplists:get_value(uploadId, P) == UploadId end, Uploads)),
    ETag.


upload_id_present(UploadId, UploadList) ->
    [] /= [UploadData || UploadData <- UploadList,
                         proplists:get_value(uploadId, UploadData) =:= UploadId].

%% source_range(undefined) -> [];
%% source_range({First, Last}) ->
%%     [{"x-amz-copy-source-range",
%%       lists:flatten(io_lib:format("bytes=~b-~b", [First, Last]))}].
