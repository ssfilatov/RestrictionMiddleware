======================
Restriction Middleware 
======================

Restriction Middleware drops out requests from users with <<admin>> role and not whitelisted source ips

Usage
-----
keystone-paste.ini::

    [filter:restriction_middleware]
    use = egg:restriction_middleware#restriction_middleware

place ip_list.txt into /etc/keystone folder

ip_list.txt example::

    192.168.10.1
    192.168.10.2
    ...
    192.168.10.10
