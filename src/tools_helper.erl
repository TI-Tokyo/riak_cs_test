%% ---------------------------------------------------------------------
%%
%% Copyright (c) 2007-2015 Basho Technologies, Inc.  All Rights Reserved.
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

-module(tools_helper).
-export([offline_delete/2]).
-include_lib("eunit/include/eunit.hrl").

%% @doc execute `offline_delete.erl` scripts with assertion at
%% before / after of it.
%% - Assert all blocks in `BlockKeysFileList` exist before execution
%% - Stop all nodes
%% - Execute `offline_delete.erl`
%% - Start all nodes
%% - Assert no blocks in `BlockKeysFileList` exist after execution
offline_delete({RiakNodes, _CSNodes} = Tussle, BlockKeysFileList) ->
    logger:info("Assert all blocks exist before deletion"),
    [assert_all_blocks_exists(RiakNodes, BlockKeysFile) ||
        BlockKeysFile <- BlockKeysFileList],

    logger:info("Stop nodes and execute offline_delete script..."),
    stop_all_nodes(Tussle),

    [begin
         Res =
             rtcs_exec:exec_priv_escript(
               1,
               "internal/offline_delete.erl",
               "-r 8 --yes " ++
                   rtcs_config:riak_bitcaskroot(rtcs_config:devpath(riak, current), 1) ++
                   " " ++ BlockKeysFile,
               #{by => riak,
                 env => [{"ERL_LIBS",
                          io_lib:format("~s/dev/dev1/riak-cs/lib/getopt-1.0.2",
                                        [rtcs_config:devpath(cs, current)])}]
                }
              ),
         logger:info("offline_delete.erl log:", []),
         [ logger:info("~s", [L]) || L <- string:tokens(Res, "\n") ],
         logger:info("offline_delete.erl log:============= END")
     end || BlockKeysFile <- BlockKeysFileList],

    logger:info("Assert all blocks are non-existent now"),
    start_all_nodes(Tussle, current),
    [assert_any_blocks_not_exists(RiakNodes, BlockKeysFile) ||
        BlockKeysFile <- BlockKeysFileList],
    logger:info("All cleaned up!"),
    ok.

assert_all_blocks_exists(RiakNodes, BlocksListFile) ->
    BlockKeys = block_keys(BlocksListFile),
    logger:info("Assert all blocks still exist."),
    [assert_block_exists(RiakNodes, BlockKey) ||
        BlockKey <- BlockKeys],
    ok.

assert_any_blocks_not_exists(RiakNodes, BlocksListFile) ->
    BlockKeys = block_keys(BlocksListFile),
    logger:info("Assert all blocks are gone."),
    [assert_block_not_exists(RiakNodes, BlockKey) ||
        BlockKey <- BlockKeys],
    ok.

block_keys(FileName) ->
    {ok, Bin} = file:read_file(FileName),
    Lines = binary:split(Bin, <<"\n">>, [global]),
    [begin
         [_BHex, _KHex, CsBucket, CsKey, UUIDHex, SeqStr] =
             binary:split(L, [<<"\t">>, <<" ">>], [global]),
         {CsBucket,
          mochihex:to_bin(binary_to_list(CsKey)),
          mochihex:to_bin(binary_to_list(UUIDHex)),
          list_to_integer(binary_to_list(SeqStr))}
     end || L <- Lines, L =/= <<>>].

assert_block_exists(RiakNodes, {CsBucket, CsKey, UUID, Seq}) ->
    ok = case rc_helper:get_riakc_obj(RiakNodes, blocks, CsBucket, {CsKey, UUID, Seq}) of
             {ok, _Obj} -> ok;
             Other ->
                 logger:error("block not found: ~p for ~p",
                              [Other, {CsBucket, CsKey, UUID, Seq}]),
                 {error, block_notfound}
         end.

assert_block_not_exists(RiakNodes, {CsBucket, CsKey, UUID, Seq}) ->
    ok = case rc_helper:get_riakc_obj(RiakNodes, blocks,
                                      CsBucket, {CsKey, UUID, Seq}) of
             {error, notfound} -> ok;
             {ok, _Obj} ->
                 logger:error("block found: ~p", [{CsBucket, CsKey, UUID, Seq}]),
                 {error, block_found}
         end.

start_all_nodes({RiakNodes, CSNodes}, Vsn) ->
    rt:pmap(fun(N) ->
                    rtcs_dev:start(N, Vsn)
            end, RiakNodes),
    ok = rt:wait_until_nodes_ready(RiakNodes),
    ok = rt:wait_until_no_pending_changes(RiakNodes),
    ok = rt:wait_until_ring_converged(RiakNodes),

    [N1|Nn] = CSNodes,
    %% let this node start stanchion
    rtcs_dev:start(N1, Vsn),
    rt:wait_until_pingable(N1),
    rt:pmap(fun(N) ->
                    rtcs_dev:start(N, Vsn),
                    rt:wait_until_pingable(N)
            end, Nn).

stop_all_nodes({RiakNodes, CSNodes}) ->
    rt:pmap(fun(N) -> rtcs_dev:stop(N) end, CSNodes),
    rt:pmap(fun(N) -> rtcs_dev:stop(N) end, RiakNodes).
