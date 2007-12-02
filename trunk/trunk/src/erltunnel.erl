%%%-------------------------------------------------------------------
%%%    BASIC INFORMATION
%%%-------------------------------------------------------------------
%%% @author  Christoph Dornheim
%%% @version 0.1
%%% @copyright 2007
%%% @doc HTTP tunnel client and server for tunneling TCP connections over HTTP
%%%
%%% Erltunnel allows client applications to establish a virtual TCP connection 
%%% to a remote server when directly connecting the server is not allowed due to 
%%% a restrictive firewall.
%%% The tunnel client runs behind the firewall and is accessed by the client application 
%%% whereas the tunnel server must reside on the internet to be able to access the server
%%% application. The tunnel server must be accessible from the tunnel client and must
%%% not be blocked by an intermediate proxy.
%%% If a virtual connection between the client and server application is established 
%%% via the tunnel client and server, all application data is transported as HTTP requests
%%% and responses between the tunnel client and server.
%%% The tunnel client sends data received from the client as an HTTP request to the
%%% tunnel server which relays the data to the server application.
%%% Conversely, the tunnel server sends data received from the server application as
%%% the related HTTP response back to the tunnel client which relays the data to the
%%% client application. Thus, tunneling a bidirectional TCP data stream is performed
%%% by periodic HTTP request/response cycles.
%%% @end
%%%-------------------------------------------------------------------
-module(erltunnel).
-author('Christoph Dornheim').

-behaviour(gen_server).

%% API
-export([start_server/2, start_link_server/2,
	 start_client/4, start_link_client/4,
	 stop/1, list/1, logtype/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

%% Types used in API functions:
%%
%% @type ip() = string() | {integer(), integer(), integer(), integer()}.
%% Name or IP of an host, e.g. "www.erlang.org", "193.180.168.20", {193,180,168,20}
%%
%% @type addr() = {ip(), integer()}.
%% Address of a connection endpoint defined by host and port number
%%
%% @type proxyOpt() = noProxy | addr() | {addr(), {string(),string()}}.
%% Specification of an optional proxy by address and by user name and password 
%% if necessary for authentication
%%
%% @type logType() = info | warn | error.
%% Logging level

%% Types used internally:
%%
%% % @type authStr() = string().
%% A base64-encoded user and password string
%% 
%% % @type proxy() = noProxy | {addr(), noAuth} | {addr(), authStr()}.
%% Proxy data used by a tunnel client that must pass a proxy
%%
%% % @type report() = [{Tag, Data} | Tag] | {Tag, Data} | Tag 
%%                    where Tag = term(), Data = term().
%% Logging report


%% The message protocol used by tunnel client and server:
%%           Client                         Server
%% -------------------------      -------------------------
%% {open, addr()}               ->
%%                            <- {ok, ConnectID} | error
%% {data, ConnectID, BinData} ->
%%                            <-  {data, ConnectID, BinData} | {close, ConnectID}
%% {close, ConnectID}         ->
%%                            <-  {close, ConnectID}
%%
%% where ConnectID = integer() and BinData = binary().


-define(CONTENTSIZE, "Content-Length: ").
-define(EOL, "\r\n").

-define(TUNNEL_SOCK_OPTS, [binary, {packet, 0}, {active, false}, {nodelay, true}]).
-define(APP_SOCK_OPTS, [binary, {packet, 0}, {active, false}, {nodelay, true}, 
			{recbuf, 1024*100}, {sndbuf, 1024*100}]).

%% Milliseconds before the next client http request is sent when data is available.
%% ( A value of 0 may cause too much load at the proxy!):
-define(MIN_REQUEST_PAUSE, 10).
%% Milliseconds before the next client http request is sent when no data is available:
-define(MAX_REQUEST_PAUSE, 500).
%% Milliseconds before the server closes a connection waiting to be reconnected.
-define(RECONNECT_TIMEOUT, 50 * ?MAX_REQUEST_PAUSE).

%% State used both by tunnel server and client: 
-record(state, {name, listenPort, listenSock,
	        listenSockOpts, connectSockOpts,
		handleConnectionFun,
	        store=store_new(),
		extState,
		logType=info}).
%% Additional state specific for tunnel server: 
-record(stateServer, {connectID=1}).
%% Additional state specific for tunnel client: 
-record(stateClient, {tunnelServerAddr, 
		      tunnelClientProxy}).

%% Data stored for any tunnel connection (both in client and server):
-record(connectData, {connectID, pid, addrsStr}).


%%====================================================================
%% API
%%====================================================================

%% @spec start_server(Name::atom(), ListenPort::integer()) -> Result::term()
%% @doc Starts a tunnel server locally registered as Name at the local port ListenPort.
%%      For the return value see gen_server:start/4.
start_server(Name, ListenPort) ->
    gen_server:start({local, Name}, ?MODULE, [server, Name, ListenPort], []).

%% @spec start_link_server(Name::atom(), ListenPort::integer()) -> Result::term()
%% @doc Same as start_server/2 where the gen_server is linked to the calling process.
%%      For the return value see gen_server:start_link/4.
start_link_server(Name, ListenPort) ->
    gen_server:start_link({local, Name}, ?MODULE, [server, Name, ListenPort], []).

%% @spec start_client(Name::atom(), ListenPort::integer(),
%%                    ServerAddr::addr(), ProxyOpt::proxyOpt()) -> Result::term()
%% @doc Starts a tunnel client locally registered as Name at the local port ListenPort.
%%      The tunnel server address is specified by ServerAddr and an optional
%%      proxy server by ProxyOpt.
%%      For the return value see gen_server:start/4. 
start_client(Name, ListenPort, ServerAddr, ProxyOpt) ->
    gen_server:start({local, Name}, ?MODULE, 
		     [client, Name, ListenPort, ServerAddr, ProxyOpt], []).

%% @spec start_link_client(Name::atom(), ListenPort::integer(),
%%                    ServerAddr::addr(), ProxyOpt::proxyOpt()) -> Result::term()
%% @doc Same as start_client where the gen_server is linked to the calling process.
%%      For the return value see gen_server:start_link/4.
start_link_client(Name, ListenPort, ServerAddr, ProxyOpt) ->
    gen_server:start_link({local, Name}, ?MODULE, 
			  [client, Name, ListenPort, ServerAddr, ProxyOpt], []).

%% @spec stop(Name::atom()) -> stopped_by_user
%% @doc Stops the specified client or server.
stop(Name) ->
    gen_server:call(Name, stop).

%% @spec list(Name::atom()) -> ok
%% @doc Prints a list of all active tunnel connections of the specified client or server.
list(Name) ->
    gen_server:call(Name, listConnectData).

%% @spec logtype(Name::atom(), Type::logType()) -> ok
%% @doc Sets the logging type. Any log information of a type equal or higher than Type
%%      will be printed at standard IO.
logtype(Name, Type) ->
    gen_server:call(Name, {logtype, Type}).


%%====================================================================
%% gen_server callbacks (called both by tunnel client and server)
%%====================================================================

%% @hidden
init([server, Name, ListenPort]) ->
    State = #state{name=Name,
		   listenPort=ListenPort,
		   handleConnectionFun=fun server_handle_connection/2,
		   listenSockOpts=?TUNNEL_SOCK_OPTS,
		   connectSockOpts=?APP_SOCK_OPTS,
		   extState=#stateServer{}},
    {ok, init_listensocket(State)};

init([client, Name, ListenPort, ServerAddr, ProxyOpt]) ->
    StateClient = #stateClient{tunnelServerAddr=ServerAddr,
			       tunnelClientProxy=get_proxy(ProxyOpt)},
    State = #state{name=Name,
		   listenPort=ListenPort,
		   handleConnectionFun=fun client_handle_connection/2, 
		   listenSockOpts=?APP_SOCK_OPTS,
		   connectSockOpts=?TUNNEL_SOCK_OPTS,
		   extState=StateClient},
    {ok, init_listensocket(State)}.

%% @hidden
handle_call(stop, _From, State) ->
    {stop, stopped_by_user, State};

handle_call({openConnect, ConnectID, FromSock, ToSock}, {FromPid,_}, State) ->
    NewState = update_connection_store(new_connection, ConnectID, FromSock, ToSock, 
				       FromPid, State),
    {reply, ok, NewState};

handle_call({getConnectData, ConnectID}, _From, State) ->
    ConnectData = store_get(State#state.store, ConnectID),
    {reply, ConnectData, State};

%% Called only by server to obtain next connection id.
handle_call(getNewConnectID, _From, State) ->
    ServerState = State#state.extState,
    ConnectID = (ServerState)#stateServer.connectID +1,
    NewState = State#state{extState=ServerState#stateServer{connectID=ConnectID}},
    {reply, ConnectID, NewState};

handle_call({updateConnectSock, ConnectID, FromSock, ToSock}, {FromPid,_}, State) ->
    NewState = update_connection_store(reconnected, ConnectID, FromSock, ToSock, 
				       FromPid, State),
    {reply, ok, NewState};

handle_call({closeConnect, ConnectID}, _From, State) ->
    {NewStore, ConnectData} = store_delete(State#state.store, ConnectID),
    NewState = State#state{store=NewStore},
    log(info, {close_connection, ConnectData}, NewState),
    {reply, ok, NewState};

handle_call(listConnectData, _From, State) ->
    ListFun = fun(ConnectData) ->
		      io:format("~p: ~p, ~p.~n", [ConnectData#connectData.connectID,
						  ConnectData#connectData.pid,
						  ConnectData#connectData.addrsStr])
	      end,
    ConnectDataList = store_get_all(State#state.store),
    lists:foreach(ListFun, ConnectDataList),
    io:format("~p connections.~n", [length(ConnectDataList)]),
    {reply, ok, State};

handle_call({logtype, Type}, _From, State) ->
    NewState = State#state{logType=Type},
    {reply, ok, NewState};

handle_call(_Request, _From, State) ->
    {reply, unknown_request, State}.

%% @hidden
handle_cast(connectAccepted, State) ->
    start_connection_acceptor(State), %% all new processes will be linked to server
    {noreply, State};

handle_cast({log, Type, Report}, State) ->
    log(Type, Report, State),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% @hidden
handle_info({'EXIT', FromPid, Reason}, State) ->
    case store_find_pid(State#state.store, FromPid) of
	none ->
	    case Reason of
		normal ->
		    ok;
		_ ->
		    %% a process linked to gen_server process has died: 
		    Report = [{some_linked_process_died, FromPid}, {reason, Reason}],
		    log(error, Report, State)
	    end,
	    NewState = State;
	ConnectData ->
	    %% a connection handling process has died:
	    {NewStore, _} = store_delete(State#state.store, 
					 ConnectData#connectData.connectID),
	    NewState = State#state{store=NewStore},
	    Report = [{close_connection_by_error, ConnectData}, {reason, Reason}],
	    log(error, Report, NewState)
    end,
    {noreply, NewState};

handle_info(_Info, State) ->
    {noreply, State}.

%% @hidden
terminate(_Reason, _State) ->
    ok.

%% @hidden
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%====================================================================
%% called by gen_server callbacks:
%%====================================================================

%% Returns the internally used proxy data.
get_proxy(noProxy) ->
    noProxy;
get_proxy({ProxyAddr, {UserStr, PasswordStr}}) ->
    {ProxyAddr, base64:encode_to_string(UserStr ++ ":" ++ PasswordStr)};
get_proxy(ProxyAddr) ->
    {ProxyAddr, noAuth}.

init_listensocket(State) ->
    process_flag(trap_exit, true),
    {ok, ListenSock} = gen_tcp:listen(State#state.listenPort, State#state.listenSockOpts),
    io:format("~p listens on port ~p.~n",[State#state.name, State#state.listenPort]),
    NewState = State#state{listenSock=ListenSock},
    start_connection_acceptor(NewState),
    NewState.

update_connection_store(Tag, ConnectID, FromSock, ToSock, Pid, State) ->
    {NewStore, ConnectData} = store_update(State#state.store, 
					   ConnectID, Pid, FromSock, ToSock),
    NewState = State#state{store=NewStore},
    log(info, {Tag, ConnectData}, NewState),
    NewState.

%% Starts a new process waiting for an incomming connection.
%% If a connection comes in, the state's function for handling connections is called.
start_connection_acceptor(State) ->
    ConnectState = State#state{store=noStore}, %% store not needed, avoid copying
    Fun = fun() ->
		  {ok, Sock} = gen_tcp:accept(ConnectState#state.listenSock),
		  gen_server:cast(ConnectState#state.name, connectAccepted),
		  %% call client or server handling:
		  (ConnectState#state.handleConnectionFun)(ConnectState, Sock)
	  end,
    spawn_link(Fun).

%% Prints Report to standard IO if Type is equal or higher than the current log type.
%% Type = logType(), Report = report()
log(Type, Report, State) ->
    case type_to_int(Type) >= type_to_int(State#state.logType) of
	true ->
	    io:format("~p ~p [~p connections]:~n", 
		      [Type, State#state.name, store_size(State#state.store)]),
	    log(Report);
	false ->
	    ok
    end.

type_to_int(Type) ->
    case Type of
	info ->
	    1;
	warn ->
	    2;
	error ->
	    3
    end.

log([]) ->
    ok;
log([First|Rest]) ->
    log(First),
    log(Rest);
log({Tag, Data}) ->
    NewData = case is_record(Data, connectData) of
		  true ->
		      lists:flatten(["ID ", integer_to_list(Data#connectData.connectID), 
				     ", Pid ", pid_to_list(Data#connectData.pid),
				     ", ",  Data#connectData.addrsStr]);
		  false ->
		      Data
	      end,
    io:format("  ~p : ~p~n", [Tag, NewData]);
log(Tag) ->
    io:format("  ~p~n", [Tag]).

store_new() ->
    gb_trees:empty().

store_size(Store) ->
    gb_trees:size(Store).

%% Return the connectData stored for ConnectID, or none. 
store_get(Store, ConnectID) ->
    case gb_trees:lookup(ConnectID, Store) of
	{value, Value} ->
	    Value;
	none ->
	    none
    end.

%% Returns a list of all connectData.
store_get_all(Store) ->
    gb_trees:values(Store).

%% Updates (add or replace) the specified connectData in Store and
%% returns {new Store, connectData}. 
store_update(Store, ConnectID, Pid, FromSock, ToSock) ->
    AddrsStr = addr_string(FromSock) ++ " -> " ++ addr_string(ToSock),
    ConnectData = #connectData{connectID=ConnectID, pid=Pid, addrsStr=AddrsStr},
    {gb_trees:enter(ConnectID, ConnectData, Store), ConnectData}.

%% Deletes the connectData stored for ConnectID from Store and
%% returns {new Store, connectData}.
store_delete(Store, ConnectID) ->
    {gb_trees:delete(ConnectID, Store), store_get(Store, ConnectID)}.

%% Returns the store's connectData containing pid, or none.
store_find_pid(Store, Pid) ->
    Iter = gb_trees:iterator(Store),
    store_find(Pid, gb_trees:next(Iter)).

store_find(_Pid, none) ->
    none;
store_find(Pid, {_Key, {_, Pid, _}, _Iter}=Result) ->
    Result;
store_find(Pid, {_Key, _Value, Iter}) ->
    store_find(Pid, gb_trees:next(Iter)).


%%====================================================================
%% tunnel client functions
%%====================================================================

%% Called by tunnel client to handle a new connection initiated by an app client.
%% This includes receiving the SOCKS4 request, opening the tunnel connection to 
%% tunnel server or an intermediate proxy server and sending a success or failure
%% SOCKS4 response to the app client. If a tunnel can be established between
%% app client and the remote app server, the tcp data is relayed between app client and
%% tunnel server.
client_handle_connection(State, AppClientSock) ->
    %% receive SOCKS4 request that contains app server addr:
    AppServerAddr = recv_SOCKS4_connect_request(AppClientSock),
    Proxy = (State#state.extState)#stateClient.tunnelClientProxy,
    TunnelServerAddr = (State#state.extState)#stateClient.tunnelServerAddr,
    ServerAddr = case Proxy of
		     noProxy ->
			 TunnelServerAddr;
		     {ProxyAddr, _} ->
			 ProxyAddr
		 end,
    %% connect to tunnel server or proxy 
    %% (the socket returned is simply denoted as TunnelServerSock):
    case gen_tcp:connect(ip(ServerAddr), port(ServerAddr), State#state.connectSockOpts) of
	{ok, TunnelServerSock} ->
	    %% send an open connection msg to tunnel server:
	    CreateHeaderFun = fun(BinSize) ->
				      create_http_request_header(TunnelServerAddr, 
								 Proxy, BinSize)
			      end,
	    ok = send_http_msg(TunnelServerSock, {open, AppServerAddr}, CreateHeaderFun),
	    %% receive response msg from tunnel server: 
	    case recv_http_msg(TunnelServerSock) of
		{ok, ConnectID} ->
		    %% tunnel successfully established:
		    ok = send_SOCKS4_connect_response(AppClientSock, AppServerAddr, true),
		    gen_server:call(State#state.name, 
				    {openConnect, ConnectID, AppClientSock, 
				     TunnelServerSock}),
		    relay_appclient_tunnelserver(State, AppClientSock, TunnelServerSock, 
						 ServerAddr, ConnectID, 
						 CreateHeaderFun, ?MIN_REQUEST_PAUSE);
		error ->
		    %% open connction failed: tunnel server cannot connect to app server:
		    send_SOCKS4_connect_response(AppClientSock, AppServerAddr, false),
		    Report = {open_connection_failed, addr_string(AppServerAddr)},
		    gen_server:cast(State#state.name, {log, warn, Report});
		{proxyErrorMsg, ProxyResponse} ->
		    %% open connction failed: the proxy has sent an error message:
		    send_SOCKS4_connect_response(AppClientSock, AppServerAddr, false),
		    Report = [{open_connection_failed, addr_string(AppServerAddr)},
			      {proxy_response, ProxyResponse}],
		    gen_server:cast(State#state.name, {log, warn, Report})
	    end;
	{error, Reason} ->
	    %% the tunnel server (or proxy) cannot be connected:
	    send_SOCKS4_connect_response(AppClientSock, AppServerAddr, false),
	    Report = [{open_connection_failed, addr_string(AppServerAddr)},
		      {tunnel_server_not_available, Reason}],
	    gen_server:cast(State#state.name, {log, error, Report})
    end.

%% Relays tcp data between app client and tunnel server.
%% A relay cycle consists of receiving data from the app client, sending it as an
%% http request to the tunnel server, receiving an http response from the
%% tunnelserver and finally sending the included data back to the app client.
relay_appclient_tunnelserver(State, AppClientSock, TunnelServerSock, ServerAddr,
			     ConnectID, CreateHeaderFun, Timeout) ->
    %% receive app client data and wrap it in a tunnel client msg:
    Msg = case gen_tcp:recv(AppClientSock, 0, Timeout) of
	      {ok, AppClientData} ->
		  {data, ConnectID, AppClientData};
	      {error, timeout} ->
		  {data, ConnectID, <<>>};
	      {error, _} ->
		  {close, ConnectID}
	  end,
    %% pause before sending http request to avoid too much proxy load:
    case Msg of
	{data, ConnectID, <<>>} ->
	    ok; %% already paused
	_ ->
	    timer:sleep(Timeout)
    end,
    %% send http request containing the tunnel client msg, possibly over a new
    %% connection to tunnel server if TunnelServerSock was closed:
    NewTunnelServerSock = try_send_http_msg(State, AppClientSock, TunnelServerSock, 
					    ServerAddr, ConnectID, Msg, CreateHeaderFun),
    %% receive tunnel server msg wrapped in a http response:
    case recv_http_msg(NewTunnelServerSock) of
	{data, ConnectID, AppServerData} ->
	    %% relay app server data to app client 
	    %% (a closed AppClientSock will be noticed in next relay cycle):
	    gen_tcp:send(AppClientSock, AppServerData),
	    NextTimeout = if 
			      Msg =/= {data, ConnectID, <<>>} ->
				  ?MIN_REQUEST_PAUSE;
			      AppServerData =/= <<>> ->
				  ?MIN_REQUEST_PAUSE;
			      true ->
				  ?MAX_REQUEST_PAUSE
			  end,
	    relay_appclient_tunnelserver(State, AppClientSock, NewTunnelServerSock, 
					 ServerAddr, ConnectID, CreateHeaderFun, 
					 NextTimeout);
	{close, ConnectID} ->
	    %% tunnel server terminates tunnel connection:
	    gen_server:call(State#state.name, {closeConnect, ConnectID});
	{proxyErrorMsg, ProxyResponse} ->
	    %% tunnel connection failure: the http response is a proxy error message
	    ConnectData = gen_server:call(State#state.name, {getConnectData, ConnectID}),
	    Report = [{error_by_proxy, ConnectData},
		      {proxy_message, ProxyResponse}],
	    gen_server:cast(State#state.name, {log, error, Report}),
	    gen_server:call(State#state.name, {closeConnect, ConnectID})
    end.

%% Sends a tunnel client msg as an http request to the tunnel server.
%% If the corresponding TunnelServerSock is closed, a new connection to the tunnel server
%% is established.
%% Returns the current (old or new) tunnel server socket.
try_send_http_msg(State, AppClientSock, TunnelServerSock, ServerAddr, 
		  ConnectID, Msg, CreateHeaderFun) ->
    case send_http_msg(TunnelServerSock, Msg, CreateHeaderFun) of
	ok ->
	    TunnelServerSock;
	closed ->
	    %% TunnelServerSock is closed, thus open a new connection to tunnel server 
	    %% or proxy server:
	    {ok, NewTunnelServerSock} = 
		gen_tcp:connect(ip(ServerAddr), port(ServerAddr), 
				State#state.connectSockOpts),
	    gen_server:call(State#state.name, 
			    {updateConnectSock, ConnectID, AppClientSock, 
			     NewTunnelServerSock}),
	    ok = send_http_msg(NewTunnelServerSock, Msg, CreateHeaderFun),
	    NewTunnelServerSock
    end.

%% Receives a SOCKS4 open connection request and returns the destination addr.
recv_SOCKS4_connect_request(AppClientSock) ->
    %% connect data in first 8 bytes:
    {ok, Bin} = gen_tcp:recv(AppClientSock,8),
    SocksVersion = 4,
    RequestCode = 1,
    <<SocksVersion:8, RequestCode:8, Port:16, IP1:8, IP2:8, IP3:8, IP4:8>> = Bin,
    recv_SOCKS4_connect_request_rest(AppClientSock),
    {{IP1, IP2, IP3, IP4}, Port}.

%% Reads the irrelevant last datagram part of variable length,
%% i.e. reading bytes from AppClientSock until the termination mark is received.
recv_SOCKS4_connect_request_rest(AppClientSock) ->
    {ok, Bin} = gen_tcp:recv(AppClientSock,0),
    EndMark = 0,
    case lists:last(binary_to_list(Bin)) of
	EndMark ->
	    ok;
	_ ->
	    recv_SOCKS4_connect_request_rest(AppClientSock)
    end.

%% Sends a SOCKS4 response datagram including whether the requested connection 
%% could be established.
send_SOCKS4_connect_response(AppClientSock, {{IP1, IP2, IP3, IP4}, Port}, Success) ->
    Version = 0, 
    ReturnCode = case Success of
		     true ->
			 90;
		     false  ->
			 91
		 end,
    gen_tcp:send(AppClientSock, 
		 <<Version:8, ReturnCode:8, Port:16, IP1:8, IP2:8, IP3:8, IP4:8>>).

%% Returns the header string for the http request sent to the tunnel server.
%% This string must be a valid http header and particularly include the lines
%% relevant for an intermediate proxy (complete tunnel server url and proxy authorization
%% header line). 
create_http_request_header(DestAddr, Proxy, BinSize) ->
    Chunks = 
	["POST ", case Proxy of
		      noProxy ->
			  "";
		      _ ->
			  %% complete tunnel server url (port 80 could be omitted)
			  %% if proxy is used:
			  ["http://", addr_string(DestAddr)]
		  end,
	 "/ HTTP/1.1", ?EOL,
	 "Host: ", addr_string(ip(DestAddr)), ?EOL,
	 "User-Agent: Erlang-Client", ?EOL,
	 ?CONTENTSIZE, integer_to_list(BinSize), ?EOL,
	 case Proxy of
	     noProxy ->
		 "";
	     {_, AuthStr} ->
		 ["Proxy-Connection: keep-alive", ?EOL,
		  case AuthStr of
		      noAuth ->
			  "";
		      _ ->
			  ["Proxy-Authorization: Basic ", AuthStr, ?EOL]
		  end]
	 end,
	 ?EOL
	],
    lists:flatten(Chunks).


%%====================================================================
%% tunnel server functions
%%====================================================================

%% Called by tunnel server to handle a new connection initiated by the tunnel client.
%% This includes receiving the tunnel client msg wrapped in an http request, 
%% opening a new connection to the destination app server, sending an http response
%% and starting the relay of data if the tunnel can be established.
%% In case the msg is for an already established but waiting connection, the msg 
%% together with TunnelClientSock is sent to the process that handles and continues 
%% that connection.
server_handle_connection(State, TunnelClientSock) ->
    %% receives the tunnel client msg wrapped in an http request:
    case recv_http_msg(TunnelClientSock) of
	{open, AppServerAddr} ->
	    %% open new connection to app server:
	    case gen_tcp:connect(ip(AppServerAddr), port(AppServerAddr), 
				 State#state.connectSockOpts) of
		{ok, AppServerSock} ->
		    %% connection successfully established:
		    ConnectID = gen_server:call(State#state.name, getNewConnectID),
		    ok = send_http_msg(TunnelClientSock, {ok, ConnectID}, 
				       fun create_http_response_header/1),
		    gen_server:call(State#state.name, 
				    {openConnect, ConnectID, TunnelClientSock, 
				     AppServerSock}),
		    relay_tunnelclient_appserver(State, TunnelClientSock, AppServerSock, 
						 ConnectID, recv);
		{error, Reason} ->
		    %% app server cannot be connected:
		    ok = send_http_msg(TunnelClientSock, error, 
				       fun create_http_response_header/1),
		    Report = [{open_connection_failed, addr_string(AppServerAddr)},
			      {reason, Reason}],
		    gen_server:cast(State#state.name, {log, error, Report})
	    end;
	{data, ConnectID, _Data}=Msg ->
	    %% msg belongs to a waiting tunnel connection:
	    sendMsgToConnection(ConnectID, Msg, TunnelClientSock, State);
	{close, ConnectID}=Msg ->
	    %% msg belongs to a waiting tunnel connection:
	    sendMsgToConnection(ConnectID, Msg, TunnelClientSock, State)
    end.

%% Sends Msg and TunnelClientSock to the process that handles the tunnel
%% connection for ConnectID. It waits for such a msg in its message queue
%% since its socket to the tunnel client was closed.
sendMsgToConnection(ConnectID, Msg, TunnelClientSock, State) ->
    ConnectData = gen_server:call(State#state.name, {getConnectData, ConnectID}),
    Pid = ConnectData#connectData.pid,
    ok = gen_tcp:controlling_process(TunnelClientSock, Pid),
    Pid ! {reconnected, TunnelClientSock, Msg}.

%% Relays tcp data between tunnel client and app server.
%% A relay cycle consists of receiving a tunnel client msg (wrapped in an http
%% request or sent by some process), sending the included data to the app server,
%% receiving data from the app server and sending that data as an http response
%% back to the tunnel client.
%% If the tunnel client socket is closed when trying to receive a msg, the process
%% waits for a reconnection message in its message queue to continue the relay.
%% This message contains a new tunnel client socket.
relay_tunnelclient_appserver(State, TunnelClientSock, AppServerSock, ConnectID, recv) ->
    %% receive tunnel client msg:
    Msg = recv_http_msg(TunnelClientSock),
    relay_tunnelclient_appserver(State, TunnelClientSock, AppServerSock, ConnectID, Msg);
relay_tunnelclient_appserver(State, TunnelClientSock, AppServerSock, ConnectID, Msg) ->
    case Msg of
 	{data, ConnectID, AppClientData} ->
	    %% send app client data to app server
	    gen_tcp:send(AppServerSock, AppClientData),
	    %% receive app server data, wrap it in a tunnel server msg 
	    %% and send it to tunnel client:
	    Reply = case gen_tcp:recv(AppServerSock, 0, 500) of
			{ok, AppServerData} ->
			    {data, ConnectID, AppServerData};
			{error, timeout} ->
			    {data, ConnectID, <<>>};
			{error, _} ->
			    {close, ConnectID}
		    end,
	    ok = send_http_msg(TunnelClientSock, Reply, 
			       fun create_http_response_header/1),
	    case Reply of
		{data, _, _} ->
		    relay_tunnelclient_appserver(State, TunnelClientSock, AppServerSock, 
						 ConnectID, recv);
		{close, _} ->
		    %% reply with closeConnect and terminate connection:
		    gen_server:call(State#state.name, {closeConnect, ConnectID})
	    end;
 	closed ->
	    %% tunnel client socket is closed but tunnel connection must be continued,
	    %% thus wait for reconnection of the tunnel client. The receiving process
	    %% will send the new socket and some msg to this process.
 	    receive
 		{reconnected, NewTunnelClientSock, NewMsg} ->
		    gen_server:call(State#state.name, 
				    {updateConnectSock, ConnectID, NewTunnelClientSock, 
				     AppServerSock}),
		    relay_tunnelclient_appserver(State, NewTunnelClientSock, 
						 AppServerSock, ConnectID, NewMsg)
	    after ?RECONNECT_TIMEOUT ->
		    %% no tunnel client reconnection within timeout:
		    ConnectData = gen_server:call(State#state.name, 
						  {getConnectData, ConnectID}),
		    Report = {reconnection_timeout, ConnectData},
		    gen_server:cast(State#state.name, {log, warn, Report}),
		    gen_server:call(State#state.name, {closeConnect, ConnectID})
 	    end;
 	{close, ConnectID} ->
	    %% app client requests closing the connection:
	    send_http_msg(TunnelClientSock, {close, ConnectID}, 
			  fun create_http_response_header/1),
	    gen_server:call(State#state.name, {closeConnect, ConnectID})
    end.

%% Returns the header string for the http response sent back to the tunnel client.
create_http_response_header(BinSize) ->
    Chunks =
	["HTTP/1.1 200 OK", ?EOL,
	 ?CONTENTSIZE, integer_to_list(BinSize), ?EOL,
	 "Date: ", httpd_util:rfc1123_date(), ?EOL,
	 ?EOL],
    lists:flatten(Chunks).


%%====================================================================
%% functions for sending and receiving the tunnel messages over http, etc.
%%====================================================================

%% Sends a http request or response to Sock. Its body contains the tunnel message Msg
%% as a binary and its header is created by CreateHeaderFun function taking the size
%% of the binary as argument.
%% Returns ok, or closed in case that Sock is closed.
send_http_msg(Sock, Msg, CreateHeaderFun) ->
    Bin = term_to_binary(Msg),
    Lines = CreateHeaderFun(size(Bin)),
    case gen_tcp:send(Sock, Lines) of
	ok ->
	    ok=gen_tcp:send(Sock, Bin); 
	{error,_Reason} ->
	    closed
    end.

%% Reads a http request or response from Sock whose body contains a tunnel message
%% as a binary.
%% Returns that message, or closed if Sock is closed. 
%% In case that the Sock is connected to a proxy server (instead of the tunnel server)
%% and the data received is an error message of the proxy server,
%% {proxyErrorMsg, ErrorMsg} is returned where ErrorMsg is a string.
recv_http_msg(Sock) ->
    inet:setopts(Sock, [list, {packet, line}]),
    case gen_tcp:recv(Sock, 0) of
	{ok, FirstLine} ->
	    BinSize = recv_header(Sock, FirstLine, 0),
	    inet:setopts(Sock, [binary, {packet, 0}]),
	    {ok, Bin} = gen_tcp:recv(Sock, BinSize),
	    try
		binary_to_term(Bin)
	    catch
		_:_ ->
		    {proxyErrorMsg, binary_to_list(Bin)} %% error msg from proxy 
	    end;
	{error, _Reason} -> %% socket closed when trying to receive
	    closed
    end.

%% Returns the size of the body contained in the header lines.
recv_header(Sock, recv, BinSize) ->
    {ok, Line} = gen_tcp:recv(Sock, 0),
    recv_header(Sock, Line, BinSize);
recv_header(Sock, Line, BinSize) ->
    case Line of
	?CONTENTSIZE ++ SizeStringEol ->
	    SizeString = string:substr(SizeStringEol, 1, 
				       string:len(SizeStringEol)-string:len(?EOL)), 
	    recv_header(Sock, recv, list_to_integer(SizeString));
	?EOL -> %% end of header
	    BinSize;
	_ ->
	    recv_header(Sock, recv, BinSize)
    end.

%% Returns a string representation of an Addr, IP or socket peername.
addr_string({IP1, IP2, IP3, IP4}) ->
    integer_to_list(IP1) ++ "." ++
    integer_to_list(IP2) ++ "." ++
    integer_to_list(IP3) ++ "." ++
    integer_to_list(IP4);
addr_string({{_IP1, _IP2, _IP3, _IP4}=IP, Port}) ->
    addr_string({addr_string(IP), Port});
addr_string({IPString, Port}) ->
    IPString ++ ":" ++ integer_to_list(Port);
addr_string(IPString) when is_list(IPString) ->
    IPString;
addr_string(Sock) ->
    {ok, {IP, Port}} = inet:peername(Sock),
    addr_string({IP, Port}).

ip({IP, _Port}) ->
    IP.
port({_IP, Port}) ->
    Port.
