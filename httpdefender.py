#!/bin/env python
#
#   httpdefender.py
#   Author:         Leslie.A.Cordell
#   CreationDate:        2013/12/14
#   ModifiedDate:        2013/12/14
#
#   The MIT License (MIT)
#   Copyright (c) 2013 Leslie.A.Cordell
#
#   This uses the http parser (httplog) and filter and
#   the signatures_conf.py file. The sole intent of this
#   script is to generate a list of malicious IPs that
#   are using scanners or bots i.e. Arachni, Siege etc,
#   with the intention of denying service to apache.
#       However, the log and filter libraries are not
#   limited just to this, this script it also capable of
#   filtering the log file using the signatures_conf.py
#   file, or whatever you want to call this file, it defaults
#   to signatures_conf.py, however you can use any name you want
#   provided the file extension is .py and it has the same
#   format as the sample file.
#       The list of malicious bots used in the config file that
#   isn't the sample, was found at this site:
#   http://wpsecure.net/bad-bot-list/
#   and checked, Arachni and Siege were added to this list.
#       An extensive list of bots can be found here:
#   http://www.user-agents.org/
#   If you were feeling creative, you could write something
#   to pull all these down, select only the non-kosher ones
#   and then add them to a dictionary.
#       The thing is however, that the dictionary is checked over
#   for each entry, this could become quite intense if you have
#   a huge file with over 300,000 lines in it etc.
#
#   One pitfall to this script is it isn't a daemonized process
#   that looks over only the recent entries in the log. It
#   imports the entire log, parses it, and then writes all of the
#   entries to a file, in the future I would like to modify this
#   to loop and read in a file stream.
#
#   Currently all this does is loop through one big file, pick out
#   the matches and stick the unique IPs in a blacklist.off file,
#   for you do load into fail2ban, firewall etc... You can do what you like
#   with these. For the future it may be cool to integrate this with something
##########################################################################
import argparse
from lib.httplog import HTTPLog, LogError, InitError, ConfigError
from lib.filter import Filter, InitErr, ConfErr
from datetime import datetime

__title__ = "httpdefender"
__author__ = "Leslie.A.Cordell"
__version__ = "1.0"
__year__ = datetime.now().year

def arguments():
    """
    Set up command-line arguments using argparse, simple options
    """
    parser = argparse.ArgumentParser(description='Run the httpdefender script.')
    parser.add_argument("-c", help="the absolute path of the apache config file. Default; /etc/httpd/conf/httpd.conf")
    parser.add_argument("-l", help="the name of the logfile defined in the config file. Default; logs/access_log")
    parser.add_argument("-p", help="the fullpath of the log in question. Default; /var/log/httpd/access_log")
    parser.add_argument("-o", help="where to output the results to. Default; blacklist.off")
    parser.add_argument("-r", help="what the results should be i.e time, host, request, agent. Default; host")
    parser.add_argument("-f", help="which signature python config file to be used. Default; signatures_conf.py")
    return parser.parse_args()


if __name__ == "__main__":
    print __title__
    banner =  "by %s %s" % (__author__, __year__)
    print banner
    print "=" * len(banner) + "\n"

    # Get the arguments
    args = arguments()
    # Set up some constants
    CONF = args.c or "/etc/httpd/conf/httpd.conf"
    LOG = args.l or "logs/access_log"
    FULLPATH = args.p or "/var/log/httpd/access_log"
    OUTPUT = args.o or "blacklist.off"
    RESULTS = args.r or "host"
    SIGNATURE_CONF = args.f or "signatures_conf.py"

    log = False
    try:
        print "opening config file %s..." % CONF
        log = HTTPLog(conf=CONF, log=LOG, fullpath=FULLPATH)
    except LogError as err:
        print err
        exit(1)
    except InitError as err:
        print err
        exit(1)
    except ConfigError as err:
        print err
        exit(1)

    if log:
        _filter = False
        try:
            print "setting up filter from config file %s..." % SIGNATURE_CONF
            _filter = Filter(log, SIGNATURE_CONF)
        except InitErr as err:
            print err
            exit(1)
        except ConfErr as err:
            print err
            exit(1)
        try:
            print "running filters for '%s' keyword" % RESULTS
            _filter.runfilter(RESULTS)
        except ConfErr as err:
            print err
            exit(1)

        if len(_filter.matches):
            try:
                print "writing output to %s..." % OUTPUT
                _blacklist = open(OUTPUT ,"w+")
                _blacklist.writelines('\n'.join(_filter.matches))
            except Exception as err:
                print err
                exit(1)

        print "httpdefender completed with %s matches!" % len(_filter.matches)

