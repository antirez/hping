Read the README file to know about the new features in general.

------ hping3 alpha2 -------

Two new features for the command line interface.

1) Using the --beep option hping will produce a beep for every matching
   packet received (not for ICMP errors).

2) The --flood option to send packets as fast as possible. This
   is much faster than "-i u1", because it's actually an endless
   loop and in this mode hping will not care to read/show replies
   at all.

------ hping3 alpha1 -------

Read the docs/API.txt for information about scripting capabilties.

Check the libs directory for examples of hping scripts.

Try the --scan option in the command line to see the port-scanner features.

  Example of the --scan option usage:

# hping3 --scan known 1.2.3.4 -S

Scanning 1.2.3.4 (1.2.3.4), port known
245 ports to scan, use -V to see all the replies
+----+-----------+---------+---+-----+-----+-----+
|port| serv name |  flags  |ttl| id  | win | len |
+----+-----------+---------+---+-----+-----+-----+
    9 discard    : .S..A...  64     0 32767    44
   13 daytime    : .S..A...  64     0 32767    44
   21 ftp        : .S..A...  64     0 32767    44
   22 ssh        : .S..A...  64     0 32767    44
   25 smtp       : .S..A...  64     0 32767    44
   37 time       : .S..A...  64     0 32767    44
   80 www        : .S..A...  64     0 32767    44
  111 sunrpc     : .S..A...  64     0 32767    44
  113 auth       : .S..A...  64     0 32767    44
  631 ipp        : .S..A...  64     0 32767    44
 3306 mysql      : .S..A...  64     0 32767    44
 6000 x11        : .S..A...  64     0 32767    44
 6667 ircd       : .S..A...  64     0  3072    44
All replies received. Done.
Not responding ports: 
