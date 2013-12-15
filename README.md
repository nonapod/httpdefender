HTTP Defender
=============

Intro
-----
After fiddling with IP Tables trying to get rid of some pesky
bots spamming an apache http server, and playing around with
a few different apache mods unsuccessfully, I took it upon
myself, as I always do, to reinvent the wheel and try to
tackle a problem using the lovely language called Python.

I wrote this in under 24 hours on a coding binge, so there's
lots of cool things that could and should be added to this.
Also because of this, you'll have to rely on the commenting
in the lib classes and your own knowledge of Python if you
indend on using the lib files and not the httpdefender file.

About
-----
httpdefender.py uses 3 files, 2 of them located in the lib
directory. The filter.py file contains the Filter class,
and the httplog.py file contains the HTTPLog class naturally.
    The httplog is (supposed to be) an intelligent log parser,
it finds out what log format you are using and then creates
an appropriate regex out of it, currently it has only been
tested on the default access_log, but it seems to be running
pretty well. It can only handle the following http log variables
at the current time:
- %h
- %l
- %u
- %t
- \"%r\"
- %>s
- %b
- \"%{User-Agent}i\"
- \"%{Referer}i\"

How To Run (default settings)
-----------------------------
To simply run the httpdefender file to accomplish the task
of removing bots. Just run the httpdefender.py file, this
assumes that:
-   you want to match it against around 150+ bots listed in the signatures_conf.py file
-   you want a unique list of all matching IPs
-   that your config file is readable and is at /var/log/httpd/access_log
-   that you want it to output all of the matching IPs to blacklist.off

If you want this, then just run httpdefender.py.

How To Run (customized settings)
--------------------------------
If you want to run httpdefender with some more customized settings
you can use the following command line arguments:
- -c    the absolute path of the apache config file. Default; /etc/httpd/conf/httpd.conf
- -l    the name of the logfile defined in the config file. Default; logs/access_log
- -p    the fullpath of the log in question. Default; /var/log/httpd/access_log
- -o    where to output the results to. Default; blacklist.off
- -r    what the results should be i.e time, host, request, agent. Default; host
- -f    which signature python config file to be used. Default; signatures_conf.py

There is a signatures_conf.py file set up, which list round about 150+ bots, including 2
I added; Siege and Arachnid. You can add more if you like from a large list here: http://www.user-agents.org/

Pitfalls
--------
Currently all this does is run through an access log and parse some host matches out
to a file by default. It is not a daemonized process that monitors a log via a file
stream and bans offending IPs on the spot. Although for the future this might be
a nice edition! If you want to fork this and make it happen, go for it!
    It's up to you how you want to deal with the IPs outputted, you might want to
drop these IPs into hosts.deny or suck them into an iptables blacklist chain or
something.
    You may also want to use the httplog and filter classes to write your own
little script using multiple different config files.

