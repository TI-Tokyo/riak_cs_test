%% -------------------------------------------------------------------
%%
%% Copyright (c) 2012 Basho Technologies, Inc.
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

%% @doc This logger backend keeps a buffer of logs in memory and returns them all
%% when the handler terminates.

-module(riak_test_logger_backend).

-behavior(gen_server).

-export([init/1,
         handle_call/3,
         handle_info/2,
         handle_cast/2,
         terminate/2,
         code_change/3]).
-export([log/2,
         get_logs/0,
         clear/0]).

-record(state, {level :: logger:level(),
                verbose :: boolean(),
                log = [unicode:chardata()]
               }).

-spec get_logs() -> [iolist()] | {error, term()}.
get_logs() ->
    gen_server:call(?MODULE, get_logs).

-spec clear() -> ok.
clear() ->
    gen_server:call(?MODULE, clear).

-spec log(logger:log_event(), logger:handler_config()) -> ok.
log(Event, Config) ->
    gen_server:call(?MODULE, {log, Event, Config}).


-spec(init(integer()|atom()|[term()]) -> {ok, #state{}} | {error, atom()}).
%% @private
%% @doc Initializes the event handler
init(Level) when is_atom(Level) ->
    init([Level, false]);
init([Level, Verbose]) ->
    {ok, #state{level = Level, verbose = Verbose}}.

-spec(handle_call(term(), pid(), #state{}) -> {ok, #state{}}).
handle_call({log,
             #{level := Level, msg := Msg, meta := #{file := File, line := Line}},
             Config},
            _From,
            #state{level=ThresholdLevel, verbose=Verbose, log = Logs} = State) ->
    case logger:compare_levels(Level, ThresholdLevel) of
        A when A == gt; A == eq ->
            FormattedMsg = logger_formatter:format(Msg, Config),
            Log = case Verbose of
                true ->
                    io_lib:format("~s | ~s:~s", [FormattedMsg, File, Line]);
                _ ->
                    FormattedMsg
            end,
            {ok, State#state{log=[Log|Logs]}};
        lt ->
            {ok, State}
    end;
handle_call(clear, _From, State) ->
    {reply, ok, State#state{log = []}};
handle_call(get_loglevel, _From, #state{level = Level} = State) ->
    {reply, Level, State};
handle_call({set_loglevel, Level}, _From, State) ->
    {reply, ok, State#state{level = Level}};
handle_call(get_logs, _From, #state{log = Logs} = State) ->
    {reply, Logs, State};
handle_call(_BadMsg, _From, State) ->
    logger:warning("don't call me that! (~p)", [_BadMsg]),
    {reply, ok, State}.

handle_cast(_Msg, State) ->
    logger:warning("not expecting any casts: ~p", [_Msg]),
    {reply, ok, State}.

-spec(handle_info(any(), #state{}) -> {ok, #state{}}).
handle_info(_, State) ->
    {ok, State}.

-spec(code_change(any(), #state{}, any()) -> {ok, #state{}}).
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

-spec(terminate(any(), #state{}) -> {ok, list()}).
terminate(_Reason, #state{log=Logs}) ->
    {ok, lists:reverse(Logs)}.
