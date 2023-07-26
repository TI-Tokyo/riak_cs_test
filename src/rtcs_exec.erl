%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2016 Basho Technologies, Inc.
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

-module(rtcs_exec).

-export([riakcmd/3,
         riakcscmd/3,
         riakcs_statuscmd/2,
         riakcs_debugcmd/3,
         riak_bitcaskroot/2,
         riakcs_home/2,
         riakcs_etcpath/2,
         exec_priv_escript/3,
         exec_priv_escript/4,
         flush_access/1, flush_access/2,
         gc/2, gc/3,
         calculate_storage/1, calculate_storage/2,
         enable_proxy_get/3,
         disable_proxy_get/3
        ]).

-include_lib("erlcloud/include/erlcloud_aws.hrl").

%% node_executable(Node) ->
%%     node_executable(Node, current).
%% node_executable(Node, Vsn) ->
%%     NodePath = rtcs_dev:node_path(Node, Vsn),
%%     WhichRiak = rtdev:which_riak(rtcs_dev:cluster_devpath(Node, Vsn)),
%%     lists:flatten(io_lib:format("~s/bin/~s", [NodePath, WhichRiak])).


riakcmd(Path, N, Cmd) ->
    lists:flatten(io_lib:format("~s ~s", [riak_binpath(Path, N), Cmd])).

riakcscmd(Path, N, Cmd) ->
    lists:flatten(io_lib:format("~s ~s", [riakcs_binpath(Path, N), Cmd])).

riakcs_statuscmd(Path, N) ->
    lists:flatten(io_lib:format("~s-admin status", [riakcs_binpath(Path, N)])).

%% riakcs_stanchioncmd(Path, N, Cmd) ->
%%     lists:flatten(io_lib:format("~s-admin stanchion ~s", [riakcs_binpath(Path, N), Cmd])).

riakcs_gccmd(Path, N, Cmd) ->
    lists:flatten(io_lib:format("~s-admin gc ~s", [riakcs_binpath(Path, N), Cmd])).

riakcs_accesscmd(Path, N, Cmd) ->
    lists:flatten(io_lib:format("~s-admin access ~s", [riakcs_binpath(Path, N), Cmd])).

riakcs_storagecmd(Path, N, Cmd) ->
    lists:flatten(io_lib:format("~s-admin storage ~s", [riakcs_binpath(Path, N), Cmd])).

riakcs_debugcmd(Path, N, Cmd) ->
    lists:flatten(io_lib:format("~s-debug ~s", [riakcs_binpath(Path, N), Cmd])).

riak_bitcaskroot(Prefix, N) ->
    lists:flatten(io_lib:format("~s/dev/dev~b/riak/data/bitcask", [Prefix, N])).

riak_binpath(Prefix, N) ->
    lists:flatten(io_lib:format("~s/dev/dev~b/~s/bin/riak", [Prefix, N, rtdev:which_riak(Prefix)])).

riakcs_home(Prefix, N) ->
    lists:flatten(io_lib:format("~s/dev/dev~b/riak-cs", [Prefix, N])).

riakcs_binpath(Prefix, N) ->
    lists:flatten(io_lib:format("~s/dev/dev~b/riak-cs/bin/riak-cs", [Prefix, N])).

riakcs_etcpath(Prefix, N) ->
    lists:flatten(io_lib:format("~s/dev/dev~b/riak-cs/etc", [Prefix, N])).

%% riakcs_libpath(Prefix, N) ->
%%     io_lib:format("~s/dev/dev~b/riak-cs/lib", [Prefix, N]).

%% riakcs_logpath(Prefix, N, File) ->
%%     io_lib:format("~s/dev/dev~b/riak-cs/log/~s", [Prefix, N, File]).

exec_priv_escript(N, Command, ScriptOptions) ->
    exec_priv_escript(N, Command, ScriptOptions, #{by => riak}).

exec_priv_escript(N, Command, ScriptOptions, #{by := By} = Options) ->
    ExecuterPrefix = rtcs_config:devpath(By, current),
    Cmd = case By of
              cs ->
                  EscriptPath = io_lib:format("priv/tools/~s", [Command]),
                  riakcscmd(ExecuterPrefix, N, "escript " ++
                                EscriptPath ++ " " ++ ScriptOptions);
              riak ->
                  EscriptPath = io_lib:format("../../../../riak_cs/dev/dev~b/riak-cs/priv/tools/~s",
                                              [N, Command]),
                  riakcmd(ExecuterPrefix, N, "escript " ++
                              EscriptPath ++ " " ++ ScriptOptions)
          end,

    rtcs_dev:cmd(Cmd, [{env, maps:get(env, Options, [])}]).

flush_access(N) -> flush_access(N, current).

flush_access(N, Vsn) ->
    Cmd = riakcs_accesscmd(rtcs_config:devpath(cs, Vsn), N, "flush"),
    rtcs_dev:cmd(Cmd).

gc(N, SubCmd) -> gc(N, SubCmd, current).

gc(N, SubCmd, Vsn) ->
    Cmd = riakcs_gccmd(rtcs_config:devpath(cs, Vsn), N, SubCmd),
    rtcs_dev:cmd(Cmd).

calculate_storage(N) ->
    calculate_storage(N, current).

calculate_storage(N, Vsn) ->
    Cmd = riakcs_storagecmd(rtcs_config:devpath(cs, Vsn), N, "batch -r"),
    rtcs_dev:cmd(Cmd).

enable_proxy_get(SrcNode, Vsn, SinkCluster) ->
    rtdev:run_riak_repl(SrcNode, rtcs_config:devpath(riak, Vsn),
                        "proxy_get enable " ++ SinkCluster).

disable_proxy_get(SrcN, Vsn, SinkCluster) ->
    rtdev:run_riak_repl(SrcN, rtcs_config:devpath(riak, Vsn),
                        "proxy_get disable " ++ SinkCluster).
