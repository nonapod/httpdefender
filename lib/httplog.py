#!/bin/env python
#
#   HTTP-OFFENDER
#   by Leslie.A.Cordell
#
#   Author:         Leslie.A.Cordell
#   CreationDate:        2013/12/13
#   ModifiedDate:        2013/12/14
#
#   The MIT License (MIT)
#   Copyright (c) 2013 Leslie.A.Cordell
#
#   It will read in the config and determine the log format,
#   and then trawl through the logs that are provided in
#   the config file.
#       First it imports the current blacklist file, if the
#   ip's found matching the signature aren't already in the
#   blacklist file, they are added. You can do whatever
#   you like with this file once it's done i.e.
#       1. Suck them into a firewall blacklist
#       2. Drop them into a hosts.deny file etc...
############################
if not "os" in vars():
    import os
if not "re" in vars():
    import re


class InitError(Exception):
    pass


class ConfigError(Exception):
    pass


class LogError(Exception):
    pass


class HTTPLog():
    """
    @Summary    This represents the HTTPLog in context, for an initializer it can take in
                the log format that is being used in APACHE to determine how the log
                is outputted, it also loads in the log that is provided to it. So multiple
                HTTPLog instances can be installed for different logs and log formats.

    @Guide      Takes in the HTTP config absolute file name used to generate the log in context,
                as well as the log filename, the filename should be as it is in the config file:
                For instance if you have the following setup:
                 CustomLog logs/access_log combined
                Then set the log keyword argument to logs/access_log, if this is the one you want
                to open.
                If you have the LogFormat for this log set up as:
                LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
                Then it will open the access_log using this format.
                    If %h and %{User-Agent} aren't both defined, then httpoffender won't work.

    @Parameters
                conf="httpd.conf file being used" i.e. conf="/etc/httpd/conf/httpd.conf"
                log="log file to check as specified in conf" i.e. logs/access_log
                fullpath="full path including log name" i.e. "/var/log/http/access_log"

    @Example    log = HTTPLog(conf="/etc/httpd/conf/httpd.conf", log="logs/access_log", base="/var/log/http/access_log")
    """
    # If it has a # at the beginning of any match, ignore it.
    # It matches CustomLog logname logtype

    ########
    # INIT #
    ########
    def __init__(self, **kwargs):
        #: Make sure we get all required kwargs
        if "log" not in kwargs or "conf" not in kwargs or "fullpath" not in kwargs:
            raise InitError("You must give the following keyword arguments; log, conf and fullpath.")

                #############
        # CONSTANTS #
        #############
        self._mask = "([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"
        #_netmatch = "(%s\.%s\.%s\.%s)" % (_mask, _mask, _mask, _mask)
        self._netmatch = "(\d{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
        #####################
        # LOG FORMAT TUPLES #
        #####################
        # apache defined log format variables, and equivalent regular expressions
        self._apachere = [
            ('%h', self._netmatch, "host"),  # The IP associated with the user
            ('%l', "(\-|.+\w)", "remotelog"),  # Usually shows up as - because this information is rarely available
            ('%u', "(\-|.+\w)", "user"),  # This is the userid, often shows up as -
            ('%t', '.*\[([0-9]{2}\/[A-Za-z]{3}\/[0-9]{1,4}:[0-9]{1,2}:[0-9]{1,2}:[0-9]{1,2}\s[+\-][0-9]{4})\].*',
                "time"),  # Timestamp of http request
            ('\\"%r\\"', '\"(.+?)\"', "request"),  # Request formed as "%m %U%q %H"
            ('%>s', "([0-9]{3})", "status"),  # Status code returned to client
            ('%b', '([0-9]{1,}|\-)', "size"),  # Size of response
            ('\\"%{User-Agent}i\\"', '\"(.+?)\"', "agent"),
            ('\\"%{Referer}i\\"', '\"(.+?)\"', "referer")
        ]

        self.conf = kwargs["conf"]
        self.fullpath = kwargs["fullpath"]
        self.log = kwargs["log"]
        self.logtype = ""
        self.logformat = ""
        self.logpath = ""
        self.logmatch = []
        self.logschema = []  # Match schema, this will give us the index of where
                               #  each of our matches will be found in matchschema

        # Open the log file and get the log type i.e. combined, referer etc
        self.getlogtype()
        # Now get the log format string
        self.getlogformat()
        # Get the matchschema
        self.getmatchschema()
        # Create a regex for the log format
        self.makelogre()
        # Open the log and parse it
        self.openlog()

        #Access the schema with -> logschema
        #Access the log matches with -> logmatch

    ####################
    # GET MATCH SCHEMA #
    ####################
    def getmatchschema(self):
        """
        A match schema will determine where abouts in the returned tuple a specific item
        of interest will be, for instance if the log has: host, referrer, and time. We
        need to know which index we can find these in the returned tuple.
        """
        _tmp = []
        _schema = []
        _dictschema = {}
        for _re in self._apachere:
            # Find the index of our log variable and stash it in tmp
            _tmp.append((_re[2], self.logformat.index(_re[0])))
            _schema.append(self.logformat.index(_re[0]))
        _schema = sorted(_schema)

        # Now we loop through the tuple list and swap out the
        # string index for the sorted _schema index to get a real
        # index.
        for _idx, _loc in enumerate(_schema):
            for _jdx, _tup in enumerate(_tmp):
                if _tmp[_jdx][1] == _loc:
                    _dictschema[_tmp[_jdx][0]] = _idx

        # Store this as our log schema dict, we'll use it as a map to find results in our
        # log result tuple
        self.logschema = _dictschema

    ############
    # OPEN LOG #
    ############
    def openlog(self):
        """
        open the logfile and parse it, creating a dictionary out of each line
        """
        self.logpath = os.path.join(self.fullpath)
        if os.path.exists(self.logpath) and os.access(self.logpath, os.R_OK):
            _log = open(self.logpath, 'r').readlines()
            for _line in _log:
                for _match in re.findall(re.compile(self.logformat), _line):
                    if _match:
                        self.logmatch.append(_match)

        else:
            raise LogError("Unable to open log; check permissions and path")

    ###############
    # MAKE LOG RE #
    ###############
    def makelogre(self):
        """
        Apply the regex's to the logformat variable to create a regular expression
        """
        # Replace any spaces with \s for regex
        self.logformat = self.logformat.replace(" ", "\s")
        # Replace the apache formatting with regex
        for _re in self._apachere:
            self.logformat = self.logformat.replace(_re[0], _re[1])

    ################
    # GET LOG TYPE #
    ################
    def getlogtype(self):
        """
        Open the config file, find the log format type we are using
        """
        if os.path.exists(self.conf) and os.access(self.conf, os.R_OK):
            _conf = open(self.conf, 'r').readlines()
            # Read the lines, match self.log only if there is no preceding comment
            _match = "^(?!\#)CustomLog.*%s.*" % self.log
            _match = re.compile(_match)
            for _line in _conf:
                if re.match(_match, _line):
                    # Get the match and store it in a global variable
                    _line = _line.split(' ')[-1]
                    self.logtype = _line
                    return

            raise ConfigError("Unable to find log; Format must follow CustomLog variable \
                              in config i.e. logs/access_log")
        # Raise an exception if we can't open the file
        else:
            raise ConfigError("Error opening config file; check permissions and path")

    ##################
    # GET LOG FORMAT #
    ##################
    def getlogformat(self):
        """
        Using the logtype variable that we extracted
        """
        if os.path.exists(self.conf) and os.access(self.conf, os.R_OK):
            _conf = open(self.conf, 'r').readlines()
            # Find the log format
            _match = "^(?!\#)LogFormat.*%s$" % self.logtype
            _match = re.compile(_match)
            for _line in _conf:
                if re.match(_match, _line):
                    # Once we get the line we need to take the format only
                    # We use _incontent to signify if we are within the format string, if we hit the opening "
                    # then we flag this as True if we hit the end " then we flag it as false
                    _incontent = False
                    _formatstring = ""
                    for _idx, _char in enumerate(_line):
                        if _idx != 0 and _char == '"' and _line[_idx - 1] != "\\":
                            # If we hit the closing quote, set _incontent to false
                            if _incontent:
                                _incontent = False
                                continue
                            # If we hit the opening quote, set _incontent to true
                            _incontent = True
                            continue
                        # If we are within the format string, append the character to _formatstring
                        if _incontent:
                            _formatstring += _char

                    if _formatstring:
                        self.logformat = _formatstring
                        return
                    else:
                        raise ConfigError("Verify LogFormat for %s exists in conf file" % self.logtype)
        # Raise an exception if we can't open the file
        else:
            raise ConfigError("Error opening config file; check permissions and path")


########
# MAIN #
########
if __name__ == '__main__':
    pass