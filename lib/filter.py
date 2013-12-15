#!/bin/env python
#
#   Filter.py
#   Author:         Leslie.A.Cordell
#   CreationDate:        2013/12/14
#   ModifiedDate:        2013/12/14
#
#   The MIT License (MIT)
#   Copyright (c) 2013 Leslie.A.Cordell
#
#   This class will simply filter out results
#   from the httplog we want to send to an output
#   file.
#
############################
if not "os" in vars():
    import os

if not "re" in vars():
    import re

if "HTTPLog" not in vars() or "httplog" not in vars():
            from lib.httplog import HTTPLog


class InitErr(Exception):
    pass


class ConfErr(Exception):
    pass


class Filter():
    """
    The filter class takes in an instance of HTTPLog, if it
    cannot be found, it will return an InitError. It also
    must take in a filename of where the signatures will be
    kept, the default is signatures.conf. There is a signatures_conf.py.sample
    file with this, check here for examples.
    """

    ########
    # INIT #
    ########
    def __init__(self, httplog, sigconf="signatures_conf.py"):
        if not isinstance(httplog, HTTPLog):
            raise InitErr("Filter requires a valid instance of HTTPLog")

        self.httplog = httplog
        self.sigconf = sigconf
        self.matches = []

    ############
    # OPENCONF #
    ############
    def openconf(self):
        """
        Open the signature config file and return the lines
        """
        if os.path.exists(self.sigconf) and os.access(self.sigconf, os.R_OK):
            return True

        else:
            raise ConfErr("Check signature config path and permissions")

    ###############
    # APPLYFILTER #
    ###############
    def applyfilter(self, signatures, filtername):
        """
        Run this against each filter in the filter conf file,
        take in the name of the filter as well as the filter
        list of regex itself
        """
        if len(signatures):
            # Make a local copy of the logschema and logmatch
            _schema = self.httplog.logschema
            _log = self.httplog.logmatch
            _sigidx = False
            _thisresults = []
            # If our filtername is in the schema
            if filtername in _schema:
                _sigidx = _schema[filtername]
            if _sigidx:
                # Well run our search against each line in the log
                for _line in _log:
                    for _signature in signatures:
                        # If we get a signature match, send it to the results list
                        if re.match(re.compile(_signature), _line[_sigidx]):
                            _thisresults.append(_line)
            return _thisresults

        else:
            return []

    #############
    # RUNFILTER #
    #############
    def runfilter(self, req="host"):
        """
        run the filter against the config file, the req value
        is what field you would like to return if there
        is a match found, by default it is host.
        """
        if self.openconf():

            # Create an empty results file
            _results = []
            # Make a local copy of the logschema
            _schema = self.httplog.logschema
            # Import the config file
            _signatures_conf = __import__(self.sigconf.replace(".py", ""))
            # Clone the signatures dictionary from signatures_conf file
            _confsignatures = _signatures_conf.signatures
            # Specify our signature types we can expect to find in our config file
            _signature_types = ["agent", "host", "remotelog", "user", "request", "status", "size", "referrer", "time"]
            for _signature in _signature_types:
                # If the signature is configured
                if _signature in _confsignatures:
                    # Apply the filter and get the results
                    _thisresults = self.applyfilter(_confsignatures[_signature], _signature)
                    for _line in _thisresults:
                        # If this result isn't already in our main results list, append it
                        if not _line in _results:
                            _results.append(_line)

            # Make sure we are unique at all times, no duplicates
            _results = list(set(_results))

            # For each result we have in our unique list, add it to our object matches
            # using our request type req, by default this is host
            for _result in _results:
                self.matches.append(_result[_schema[req]])

            # Now truncate our main object matches to have only uniques
            self.matches = list(set(self.matches))


