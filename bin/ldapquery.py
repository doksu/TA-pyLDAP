#!/usr/bin/env python

from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
import sys
import os
import ldap

@Configuration(type='reporting')
class LDAPQueryCommand(GeneratingCommand):

    uri = Option(require=True)
    verifycert = Option(require=False, validate=validators.Boolean())
    scope = Option(require=False)
    basedn = Option(require=True)
    binddn = Option(require=False)
    bindpassword = Option(require=False)
    ldapfilter = Option(require=False)
    attributelist = Option(require=False)

    def generate(self):

        # Phase 1: Preparation

        if not (self.uri[:7] == "ldap://" or self.uri[:8] == "ldaps://"):
            raise Exception("Please specify the protocol ldap or ldaps in the uri.")

        if self.scope:
            if self.scope == "base":
                self.scope = ldap.SCOPE_BASE
            elif self.scope == "onelevel":
                self.scope = ldap.SCOPE_ONELEVEL
            elif self.scope == "subtree":
                self.scope = ldap.SCOPE_SUBTREE
            else:
                raise Exception("Invalid scope filter given. Please use: base, onelevel, subtree")
        else:
            self.scope = ldap.SCOPE_SUBTREE

        if not self.ldapfilter:
            self.ldapfilter = "(objectClass=*)"

        if self.attributelist:
            self.attributelist = str(self.attributelist).split()
        else:
            self.attributelist = None

        # Phase 2: Connect to LDAP server and run search

        l = ldap.initialize(str(self.uri))

        try:
            if self.verifycert:
                l.set_option(ldap.OPT_X_TLS_DEMAND, self.verifycert)
        except:
            pass

        if self.binddn:
            if self.bindpassword:
                try:
                    l.simple_bind_s(self.binddn, self.bindpassword)
                except ldap.INVALID_CREDENTIALS:
                    raise Exception("Credentials provided failed to bind to directory.")
                except:
                    raise Exception("Failed to bind to directory. Please check arguments provided and network connectivity.")
            else:
                raise Exception("Please provide bindpassword argument for authenticated binds.")

        try:
            # run the search
            result_id = l.search(self.basedn, self.scope, self.ldapfilter, self.attributelist)

        except ldap.LDAPError, error:
            if type(error.message) == dict and error.message.has_key('desc'):
                raise Exception(str(error.message['desc']))
            else:
                raise Exception(str(error))

        except:
            raise Exception("LDAP query failed. Please check arguments provided and network connectivity.")

        if self.binddn:
            l.unbind_s()

        # Phase 3: Send results to Splunk

        # When providing large datasets to Splunk, if Splunk determines certain fields are uncommon (which is likely with sparsely populated directory attributes), it will drop them resulting in an incomplete dataset for the user, so we take two passes here over the returned results to prevent fields being dropped. The first pass caches the results and determines all the attributes in the result set. The second pass adds any missing fields to all the results before sending to Splunk.

        cache = []
        attributes = set()

        # results are returned asynchronously so we need to loop until no more entries are provided
        while True:
            result_type, result_data = l.result(result_id, 0)
            if result_type == ldap.RES_SEARCH_ENTRY:
                    # for future reference the entries used below looks like this: [('uid=username,ou=users,dc=example,dc=com', {'cn': ['Example'], 'mail': ['username@example.com']})]
                    entry = result_data[0][1]
                    entry["dn"] = result_data[0][0]
                    attributes.update(entry.keys())
                    cache += [entry]
            else:
                    break

        # add any missing fields to the results
        for entry in cache:
            for attribute in attributes:
                if attribute not in entry:
                    entry[attribute] = []

            yield entry

dispatch(LDAPQueryCommand, sys.argv, sys.stdin, sys.stdout, __name__)
