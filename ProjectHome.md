An HTTP tunnel allows client applications to establish a virtual TCP connection to a remote server when directly connecting the server is not allowed due to a restrictive firewall.
Access from clients behind the firewall to servers located on the internet is often controlled by an intermediate web proxy which permits or denies outgoing connections depending on a set of individually defined access rules.
[Squid](http://www.squid-cache.org), for example, is a widely used web proxy with fine-grained control of which remote hosts and ports the clients are allowed to connect.
Moreover, Squid can block HTTP requests or responses by inspecting their headers.
Most proxies probably permit access to HTTP, HTTPS and FTP servers at their standard ports, but in a most restrictive case, only HTTP at standard port 80 might be allowed.
If your client application needs access to some remote server but cannot pass the firewall and adjusting the access rules is not an option (due to configuration cost or lack of permission), the only way to connect to the server is by tunneling the intended connection through a connection that passes the firewall.

An HTTP tunnel software consists of a tunnel client and server.
The tunnel client runs behind the firewall and is accessed by the client application whereas the tunnel server must reside on the internet to be able to access the server application.
Most notably, the tunnel server must be accessible from the tunnel client and must not be blocked by an intermediate proxy.
If a virtual connection between the client and server application is established via the tunnel client and server, all application data is transported as HTTP requests and responses between the tunnel client and server.
The tunnel client sends data received from the client as an HTTP request to the tunnel server which relays the data to the server application.
Conversely, the tunnel server sends data received from the server application as the related HTTP response back to the tunnel client which relays the data to the client application.
Thus, tunneling a bidirectional TCP data stream is performed by periodic HTTP request/response cycles.

Erltunnel is written in [Erlang](http://www.erlang.org), a functional programming language designed for concurrent and distributed computing.
Erlang is a battle-tested platform particularly for network programming since it provides, among other things, a lightweight, OS-independent process model which makes Erlang cope with a large number of processes.
In contrast to heavyweight shared-memory threads, this encourages managing a large number of network connections on a per-process basis.

Erltunnel is an HTTP tunnel with a small set of API functions.
It is tested using the latest Erlang release on Ubuntu Linux but should run as well on other platforms.
It is tested in particular to pass the Squid proxy.
Remember, however, that whether the tunnel client can connect to the tunnel server may depend on the individually defined access rules.
For example, the HTTP request might be refused because the user-agent header line does not mention the right client application the proxy is configured for.
In such a situation you have to adjust the code that produces the header lines in order to match your specific needs.
The Erltunnel code is written with focus on simplicity, thus modifying these functions should be straightforward.

Erltunnel currently provides the following features:
  * tunneling any TCP/IP connections over persistent or non-persistent HTTP connections
  * tunnel client accessible by SOCKS 4 proxy protocol, i.e. client application must understand SOCKS 4
  * tunneling with or without an intermediate proxy
  * optional proxy authentication (user, password)