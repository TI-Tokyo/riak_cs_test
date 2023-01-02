%% -------------------------------------------------------------------
%%
%% Copyright (c) 2013-2014 Basho Technologies, Inc.
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

%% @private
-module(rtdev).

-export([append_to_conf_file/2,
         get_deps/0,
         node_id/1,
         node_version/1,
         run_riak/3,
         run_riak_repl/3,
         which_riak/1]).

-include_lib("eunit/include/eunit.hrl").

-define(PATH, (rt_config:get(rtdev_path))).
get_deps() ->
    RelPath = relpath(current),
    lists:flatten(io_lib:format("~s/dev/dev1/~s/lib", [RelPath, which_riak(RelPath)])).

riakcmd(Path, Node, Cmd) ->
    N = node_id(Node),
    WhichRiak = which_riak(Path),
    ExecName = rt_config:get(exec_name, WhichRiak),
    io_lib:format("~s/dev/dev~b/~s/bin/~s ~s", [Path, N, WhichRiak, ExecName, Cmd]).

riakreplcmd(Path, N, Cmd) ->
    io_lib:format("~s/dev/dev~b/riak/bin/riak-repl ~s", [Path, N, Cmd]).

run_riak(Node, Path, Cmd) ->
    Exec = riakcmd(Path, Node, Cmd),
    logger:info("Exec ~s", [Exec]),
    R = os:cmd(Exec),
    case Cmd of
        "start" ->
            rt_cover:maybe_start_on_node(Node, node_version(Node)),
            %% Intercepts may load code on top of the cover compiled
            %% modules. We'll just get no coverage info then.
            maybe_load_intercepts(Node),
            R;
        "stop" ->
            rt_cover:maybe_stop_on_node(Node),
            R;
        _ ->
            R
    end.

maybe_load_intercepts(Node) ->
    case rt_intercept:are_intercepts_loaded(Node) of
        false ->
            ok = rt_intercept:load_intercepts([Node]);
        true ->
            ok
    end.


run_riak_repl(Node, Path, Cmd) ->
    logger:info("Running: ~s", [riakcmd(Path, Node, Cmd)]),
    os:cmd(riakreplcmd(Path, node_id(Node), Cmd)).
    %% don't mess with intercepts and/or coverage,
    %% they should already be setup at this point

relpath(Vsn) ->
    Path = ?PATH,
    relpath(Vsn, Path).

relpath(Version, Paths=[{_,_}|_]) ->
    rt_util:find_atom_or_string_dict(Version, orddict:from_list(Paths));
relpath(current, Path) ->
    Path;
relpath(root, Path) ->
    Path;
relpath(_, _) ->
    throw("Version requested but only one path provided").

append_to_conf_file(File, NameValuePairs) ->
    Settings = lists:flatten(
                 [io_lib:format("~n~s = ~s~n", [Name, Value])
                  || {Name, Value} <- NameValuePairs]),
    file:write_file(File, Settings, [append]).

node_id(Node) ->
    NodeMap = rt_config:get(rt_nodes),
    orddict:fetch(Node, NodeMap).

node_version(N) ->
    VersionMap = rt_config:get(rt_versions),
    rt_util:find_atom_or_string_dict(N, VersionMap).

check_node({_N, Version}) ->
    case rt_util:find_atom_or_string(Version, rt_config:get(rtdev_path)) of
        undefined ->
            logger:error("You don't have Riak ~s installed or configured", [Version]),
            erlang:error(lists:flatten(io_lib:format("You don't have Riak ~p installed or configured", [Version])));
        _ -> ok
    end.

-spec which_riak(string()) -> string().
which_riak(S) ->
    case lists:reverse(string:split(S, "/", all)) of
        ["", "riak" | _] -> "riak";
        ["riak" | _] -> "riak";
        ["", "riak_cs" | _] -> "riak-cs";
        ["riak_cs" | _] -> "riak-cs";
        _ -> ""
    end.


-ifdef(TEST).

release_versions_test() ->
    ok = rt_config:set(rtdev_path, [{root, "/Users/hazen/dev/rt/riak"},
             {current, "/Users/hazen/dev/rt/riak/current"},
             {previous, "/Users/hazen/dev/rt/riak/riak-2.0.6"},
             {legacy, "/Users/hazen/dev/rt/riak/riak-1.4.12"},
             {'2.0.2', "/Users/hazen/dev/rt/riak/riak-2.0.2"},
             {"2.0.4", "/Users/hazen/dev/rt/riak/riak-2.0.4"}]),
    ?assertEqual(ok, check_node({foo, '2.0.2'})),
    ?assertEqual(ok, check_node({foo, "2.0.4"})),
    ?assertEqual("/Users/hazen/dev/rt/riak/current", relpath(current)),
    ?assertEqual("/Users/hazen/dev/rt/riak/riak-2.0.2", relpath('2.0.2')),
    ?assertEqual("/Users/hazen/dev/rt/riak/riak-2.0.4", relpath("2.0.4")).

-endif.
