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

-export([multipart_upload/4]).

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
    logger:debug("UploadId: ~p", [UploadId]),
    logger:debug("PartEtag: ~p", [PartEtag]),
    upload_parts(Bucket, Key, UploadId, Config, PartCount + 1,
                 Sizes, [Content | Contents], [{PartCount, PartEtag} | Parts]).
