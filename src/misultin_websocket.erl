% ==========================================================================================================
% MISULTIN - WebSocket
%
% >-|-|-(°>
% 
% Copyright (C) 2010, Roberto Ostinelli <roberto@ostinelli.net>, Joe Armstrong.
% All rights reserved.
%
% Code portions from Joe Armstrong have been originally taken under MIT license at the address:
% <http://armstrongonsoftware.blogspot.com/2009/12/comet-is-dead-long-live-websockets.html>
%
% BSD License
% 
% Redistribution and use in source and binary forms, with or without modification, are permitted provided
% that the following conditions are met:
%
%  * Redistributions of source code must retain the above copyright notice, this list of conditions and the
%	 following disclaimer.
%  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
%	 the following disclaimer in the documentation and/or other materials provided with the distribution.
%  * Neither the name of the authors nor the names of its contributors may be used to endorse or promote
%	 products derived from this software without specific prior written permission.
%
% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
% WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
% PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
% ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
% TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
% HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
% NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
% POSSIBILITY OF SUCH DAMAGE.
% ==========================================================================================================
-module(misultin_websocket).
-vsn("0.6.0").

% API
-export([check/2, connect/3]).
-export([crunch_ws_key/1, crunch_ws_key_parts/2]).


% includes
-include("../include/misultin.hrl").


% records
-record(ws_handshake, {
  upgrade=no,
  connection=no,
  host=no,
  origin=no,
  key1=no,
  key2=no
}).


% ============================ \/ API ======================================================================

% Function: {true, Origin, Host, Path} | false
% Description: Check if the incoming request is a websocket handshake.
check(Path, Headers) ->
	?LOG_DEBUG("testing for a websocket request, path: ~p headers: ~p", [Path, Headers]),
	case check_ws_headers(Headers) of
    {ok,Host,Origin} ->
			% websockets request WITHOUT Sec-Websocket-Key(1|2).  Dangerous to accept.
			{true, Origin, Host, Path, []};
    {ok,Host,Origin,Key1,Key2} ->
      % websockets request WITH Sec-Websocket-Key(1|2).  See http://www.whatwg.org/specs/web-socket-protocol/
      SecurityKeys={Key1,Key2},
      {true, Origin, Host, Path, SecurityKeys};
		_Else ->
			% normal HTTP request
			false
	end.

% Connect and handshake with Websocket.
connect(#ws{socket = Socket, socket_mode = SocketMode, origin = Origin, host = Host, path = Path} = Ws, SecurityKeys, WsLoop) ->
	?LOG_DEBUG("received websocket handshake request", []),
	HandshakeServer = ["HTTP/1.1 101 Web Socket Protocol Handshake\r\n",
		"Upgrade: WebSocket\r\n",
		"Connection: Upgrade\r\n",
		"Sec-WebSocket-Origin: ", Origin , "\r\n",
		"Sec-WebSocket-Location: ws://", lists:concat([Host, Path]), "\r\n\r\n"
	],
	% send handshake back
	misultin_socket:send(Socket, HandshakeServer, SocketMode),
  % set opts for reading security header and subsequent data
  misultin_socket:setopts(Socket, [{packet, 0}, {active, true}], SocketMode),
  % listen for final security piece of handshake
  Success = case SecurityKeys of
    {Key1, Key2} ->
      receive
        {tcp, _Socket, Data} when size(Data) == 8 ->
          CKey1 = crunch_ws_key(Key1),
          CKey2 = crunch_ws_key(Key2),
          Md5Source = <<CKey1:32, CKey2:32, Data/binary>>,
          Md5 = erlang:md5(Md5Source),
          ?LOG_DEBUG("CKey1/CKey2/Data/Secure Response: ~p/~p/~p/~p", [CKey1, CKey2, Data, Md5]),
          misultin_socket:send(Socket, Md5, SocketMode),
          true
        after 5000 ->
          ?LOG_DEBUG("Valid security data NOT received - expected 8 bytes", [ ]),
          misultin_socket:close(Socket),
          false
      end;
    _ ->
      true
  end,
  case Success of
    false -> ok;
    true ->
      % set opts for reading data
      misultin_socket:setopts(Socket, [{packet, 0}, {active, true}], SocketMode),
      % add main websocket pid to misultin server reference
      misultin:persistent_socket_pid_add(self()),
      % initialize the sending interface
      Ws0 = misultin_ws:new(Ws, self()),
      % spawn controlling process
      WsHandleLoopPid = spawn(fun() -> WsLoop(Ws0) end),
      erlang:monitor(process, WsHandleLoopPid),
      % start listening for incoming data
      ws_loop(Socket, none, WsHandleLoopPid, SocketMode)
  end.
	
% ============================ /\ API ======================================================================


% ============================ \/ INTERNAL FUNCTIONS =======================================================
  
% Checks for non-normative header ordering ... As per specs from
% http://www.whatwg.org/specs/web-socket-protocol/
% : "Fields in the handshake are sent by the client in a random order; the
%    order is not meaningful."
% Find [{'Upgrade', "WebSocket"}, {'Connection', "Upgrade"}, {'Host', Host}, {"Origin", Origin}|_RH]
check_ws_headers(Headers) ->
  case check_ws_headers_util(#ws_handshake{}, Headers) of
    #ws_handshake{upgrade=ok, connection=ok, host=Host, origin=Origin, key1=no, key2=no} when Host =/= no, Origin =/= no -> {ok,Host,Origin};
    #ws_handshake{upgrade=ok, connection=ok, host=Host, origin=Origin, key1=Key1, key2=Key2} 
      when Host =/= no, Origin =/= no, Key1 =/= no, Key2 =/= no -> 
      {ok,Host,Origin,Key1,Key2};
    _ -> {error,missing_headers}
  end.
    
check_ws_headers_util(Result=#ws_handshake{}, []) ->
  Result;
check_ws_headers_util(Result=#ws_handshake{upgrade=no}, [{'Upgrade', "WebSocket"}|T]) ->
  check_ws_headers_util(Result#ws_handshake{upgrade=ok}, T);
check_ws_headers_util(Result=#ws_handshake{connection=no}, [{'Connection',"Upgrade"}|T]) ->
  check_ws_headers_util(Result#ws_handshake{connection=ok}, T);
check_ws_headers_util(Result=#ws_handshake{host=no}, [{'Host', Host}|T]) ->
  check_ws_headers_util(Result#ws_handshake{host=Host}, T);
check_ws_headers_util(Result=#ws_handshake{origin=no}, [{"Origin", Origin}|T]) ->
  check_ws_headers_util(Result#ws_handshake{origin=Origin}, T);
check_ws_headers_util(Result=#ws_handshake{key1=no}, [{"Sec-WebSocket-Key1", Key1}|T]) ->
  check_ws_headers_util(Result#ws_handshake{key1=Key1}, T);
check_ws_headers_util(Result=#ws_handshake{key2=no}, [{"Sec-WebSocket-Key2", Key2}|T]) ->
  check_ws_headers_util(Result#ws_handshake{key2=Key2}, T);
% --Firefox has an uncapitalized s... Reported as bug https://bugzilla.mozilla.org/show_bug.cgi?id=582408--
check_ws_headers_util(Result=#ws_handshake{key1=no}, [{"Sec-Websocket-Key1", Key1}|T]) ->
  check_ws_headers_util(Result#ws_handshake{key1=Key1}, T);
check_ws_headers_util(Result=#ws_handshake{key2=no}, [{"Sec-Websocket-Key2", Key2}|T]) ->
  check_ws_headers_util(Result#ws_handshake{key2=Key2}, T);
% --End Firefox hacks...--
check_ws_headers_util(Result, [_|T]) ->
  check_ws_headers_util(Result, T).
  
% Parses a key header field as per the opening handshake for websockets
crunch_ws_key(Key) ->
  {Number,Spaces} = crunch_ws_key_parts({0,0}, Key),
  Number div Spaces.
  
crunch_ws_key_parts(Result={_Number, _Spaces}, []) ->
  Result;
crunch_ws_key_parts({Number,Spaces}, [H|T]) when $0 =< H, $9 >= H ->
  crunch_ws_key_parts({Number * 10 + (H - $0), Spaces}, T);
crunch_ws_key_parts({Number,Spaces}, [$ |T]) ->
  crunch_ws_key_parts({Number, Spaces + 1}, T);
crunch_ws_key_parts(Result, [_|T]) ->
  crunch_ws_key_parts(Result, T).

% Main Websocket loop
ws_loop(Socket, Buffer, WsHandleLoopPid, SocketMode) ->
	receive
		{tcp, Socket, Data} ->
			handle_data(Buffer, binary_to_list(Data), Socket, WsHandleLoopPid, SocketMode);
		{tcp_closed, Socket} ->
			?LOG_DEBUG("tcp connection was closed, exit", []),
			% close websocket and custom controlling loop
			websocket_close(Socket, WsHandleLoopPid, SocketMode);
		{'DOWN', Ref, process, WsHandleLoopPid, Reason} ->
			case Reason of
				normal ->
					?LOG_DEBUG("linked websocket controlling loop stopped.", []);
				_ ->
					?LOG_ERROR("linked websocket controlling loop crashed with reason: ~p", [Reason])
			end,
			% demonitor
			erlang:demonitor(Ref),
			% close websocket and custom controlling loop
			websocket_close(Socket, WsHandleLoopPid, SocketMode);
		{send, Data} ->
			?LOG_DEBUG("sending data to websocket: ~p", [Data]),
			misultin_socket:send(Socket, [0, Data, 255], SocketMode),
			ws_loop(Socket, Buffer, WsHandleLoopPid, SocketMode);
		shutdown ->
			?LOG_DEBUG("shutdown request received, closing websocket with pid ~p", [self()]),
			% close websocket and custom controlling loop
			websocket_close(Socket, WsHandleLoopPid, SocketMode);
		_Ignored ->
			?LOG_WARNING("received unexpected message, ignoring: ~p", [_Ignored]),
			ws_loop(Socket, Buffer, WsHandleLoopPid, SocketMode)
	end.

% Buffering and data handling
handle_data(none, [255,0], _Socket, _WsHandleLoopPid, _SocketMode) ->
  self() ! shutdown;
handle_data(none, [0|T], Socket, WsHandleLoopPid, SocketMode) ->
	handle_data([], T, Socket, WsHandleLoopPid, SocketMode);
handle_data(none, [], Socket, WsHandleLoopPid, SocketMode) ->
	ws_loop(Socket, none, WsHandleLoopPid, SocketMode);
handle_data(L, [255|T], Socket, WsHandleLoopPid, SocketMode) ->
	WsHandleLoopPid ! {browser, lists:reverse(L)},
	handle_data(none, T, Socket, WsHandleLoopPid, SocketMode);
handle_data(L, [H|T], Socket, WsHandleLoopPid, SocketMode) ->
	handle_data([H|L], T, Socket, WsHandleLoopPid, SocketMode);
handle_data([], L, Socket, WsHandleLoopPid, SocketMode) ->
	ws_loop(Socket, L, WsHandleLoopPid, SocketMode).

% Close socket and custom handling loop dependency
websocket_close(Socket, WsHandleLoopPid, SocketMode) ->
	% remove main websocket pid from misultin server reference
	misultin:persistent_socket_pid_remove(self()),
	% kill custom handling loop process
	exit(WsHandleLoopPid, kill),
	% close main socket
	misultin_socket:close(Socket, SocketMode).

% ============================ /\ INTERNAL FUNCTIONS =======================================================
