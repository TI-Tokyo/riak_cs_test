%% -------------------------------------------------------------------
%%
%% Copyright (c) 2016 Basho Technologies, Inc.
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

-ifndef(job_enable_common_included).
-define(job_enable_common_included, true).

-define(ADVANCED_CONFIG_KEY,    'job_accept_class').
-define(CUTTLEFISH_PREFIX,      "cluster.job").

-define(TOKEN_LIST_BUCKETS,     {riak_kv, list_buckets}).
-define(TOKEN_LIST_KEYS,        {riak_kv, list_keys}).
-define(TOKEN_SEC_INDEX,        {riak_kv, secondary_index}).
-define(TOKEN_LIST_BUCKETS_S,   {riak_kv, stream_list_buckets}).
-define(TOKEN_LIST_KEYS_S,      {riak_kv, stream_list_keys}).
-define(TOKEN_SEC_INDEX_S,      {riak_kv, stream_secondary_index}).
-define(TOKEN_MAP_REDUCE,       {riak_kv, map_reduce}).
-define(TOKEN_MAP_REDUCE_JS,    {riak_kv, map_reduce}).
-define(TOKEN_YZ_SEARCH,        {yokozuna, query}).
-define(TOKEN_OLD_SEARCH,       {riak_search, query}).

-define(ERRMSG_BIN(Tok), riak_core_util:job_class_disabled_message(binary, Tok)).
-define(ERRMSG_TXT(Tok), riak_core_util:job_class_disabled_message(text, Tok)).

-endif. % job_enable_common_included
