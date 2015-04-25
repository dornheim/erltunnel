# Squid ACL for Testing Erltunnel #
If you want to test Erltunnel in combination with the Squid proxy, you have to make sure to get Squid running on your local machine (an installation guide can be found [here](http://linux.cudeso.be/linuxdoc/squid.php)).
The access control lists (ACLs) are defined in the file `squid.conf` (located e.g. at `/etc/squid` on the Ubuntu system).
The default `squid.conf` is rather lengthy and does not allow the tunnel client to connect the tunnel server at port 3000 that we used for testing Erltunnel.
It only allows connections to standard ports that might be already bound on your system.

Below you find two small `squid.conf` files that match our needs for testing Erltunnel with and without user authentication.
Replacing the default `squid.conf` with one of them might be simpler than correctly modifying it.
Note that Squid must be restarted to read a new or modified `squid.conf`.
This can be done with `/etc/init.d/squid restart`.

## squid.conf with authentication ##
Squid's configuration for user authentication, in particular the generation of the password file is described
[here](http://www.linuxhomenetworking.com/wiki/index.php/Quick_HOWTO_:_Ch32_:_Controlling_Web_Access_with_Squid).
The following `squid.conf` assumes that the passwords are defined in the file `/etc/squid/squid_passwd`.

```
# Squid normally listens on port 3128
http_port 3128

# cache directory
cache_dir ufs /var/spool/squid 100 16 256

visible_hostname ubuntubox

## ACL elements (values are combined by OR)
acl all src 0.0.0.0/0.0.0.0
acl localhost src 127.0.0.1/255.255.255.255

## allowed destination ports: standard http and https and tunnel server port:
acl dest_ports port 80 443 3000

## Authentication configuration 
## ncsa_auth file and password file:
auth_param basic program /usr/lib/squid/ncsa_auth /etc/squid/squid_passwd
acl ncsa_users proxy_auth REQUIRED

## access rules (elements are combined by AND)

## allow access with authentication:
http_access allow localhost dest_ports ncsa_users

http_access deny all
```

## squid.conf without authentication ##
```
# Squid normally listens on port 3128
http_port 3128

# cache directory
cache_dir ufs /var/spool/squid 100 16 256

visible_hostname ubuntubox

## ACL elements (values are combined by OR)
acl all src 0.0.0.0/0.0.0.0
acl localhost src 127.0.0.1/255.255.255.255

## allowed destination ports: standard http and https and tunnel server port:
acl dest_ports port 80 443 3000

## access rules (elements are combined by AND)

## allow access without authentication:
http_access allow localhost dest_ports

http_access deny all

```