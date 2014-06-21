# sv_server.py
# python3
# Code for server portion of simulated election
# Simulates array of servers for mix
#  but not SBB or proof servers

##############################################################################
# standard MIT open-source license
##############################################################################
"""
The MIT License

Copyright (c) 2014 Michael O. Rabin and Ronald L. Rivest

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
##############################################################################
# end of standard MIT open-source license
##############################################################################

import sys

import sv
# import sv_sbb
import sv_election

class Server():

    """ Implement server (for proofs and tally).

    An object of this class implements a complete 2D server array;
    for a real implementation these would be implemented
    in a distributed manner with a distinct server for each element
    of the array.
    """

    def __init__(self, election, n_fail, n_leak):
        """ Initialize server.  This is one for the whole election.

        The server array has the given number of rows and columns
        as parts or sub-servers.  Here we simulate the actions of
        these sub-servers.
        n_fail = number of servers that could fail
        n_leak = number of servers that my leak information
        """

        assert isinstance(election, sv_election.Election)
        assert isinstance(n_fail, int) and n_fail >= 0
        assert isinstance(n_leak, int) and n_leak >= 0

        self.election = election
        self.n_fail = n_fail
        self.n_leak = n_leak

        if self.n_fail > 0:
            self.cols = 1 + n_leak
            self.rows = 2 + n_fail + n_leak
            self.threshold = 2 + n_leak   # number of rows needed to reconstruct
        else:
            self.cols = 1 + n_leak
            self.rows = 1 + n_leak
            self.threshold = 1 + n_leak
        rows = self.rows
        cols = self.cols
        threshold = self.threshold

        # each row has an identifier in "abcd..."
        assert rows <= 26
        self.row_list = "abcdefghijklmnopqrstuvwxyz"[:rows]

        # The state of the server in row i, col j is represented
        # here in the dictionary P[race_id][i][j] for the given race
        # where  i in row_list  and 0 <= j < cols.

        # create one top-level dict sdb as database for this main server
        self.sdb = dict()

        # within the top level dict sdb, create a three-dimensional array of
        # sub-dicts for data storage, each addressed as sdb[race_id][i][j]
        for race in election.races:
            race_id = race.race_id
            self.sdb[race_id] = dict()
            for i in self.row_list:
                self.sdb[race_id][i] = dict()
                for j in range(cols):
                    self.sdb[race_id][i][j] = dict()

        # each server has its own random-number source for each race
        # in practice, these could be derived from true random seeds input
        # independently to each server
        for race_id in election.race_ids:
            for i in self.row_list:
                for j in range(cols):
                    rand_name = "server:" + race_id + ":" + \
                                str(i) + ":" + str(j)
                    self.sdb[race_id][i][j]['rand_name'] = rand_name
                    sv.init_randomness_source(rand_name)

        # within each sub-dict sdb[race_id][i][j] create a variety of lists for
        # storage of cast votes and associated data, including 2m-way replicated
        # lists needed for the 2m mixes (passes) needed.
        for race_id in election.race_ids:
            for i in self.row_list:
                # first-column lists for storing cast votes and secrets
                sdbp = self.sdb[race_id][i][0]
                sdbp['ballot_id'] = dict()   # ballot_id (indices from p_list)
                sdbp['cast_votes'] = dict()  # (com(u),com(v)) pairs
                sdbp['x'] = dict()           # choice x, where x = u+v mod M
                sdbp['u'] = dict()           # u
                sdbp['v'] = dict()           # v
                sdbp['ru'] = dict()          # randomness to open com(u)
                sdbp['rv'] = dict()          # randomness to open com(v)
                # for all columns, have 2m-way replicated data structures
                for j in range(cols):
                    sdbp = self.sdb[race_id][i][j]
                    for k in election.k_list:
                        sdbp[k] = dict()
                        sdbp[k]['x'] = dict()    # inputs on pass k
                        sdbp[k]['y'] = dict()    # outputs on pass k
                # last-column lists for storing published lists of commitments
                for k in election.k_list:
                    sdbp = self.sdb[race_id][i][self.cols-1][k]
                    sdbp['y'] = dict()
                    sdbp['u'] = dict()
                    sdbp['v'] = dict()
                    sdbp['ru'] = dict()
                    sdbp['rv'] = dict()
                    sdbp['pair'] = dict()
        # post on log that server array is set up
        election.sbb.post("setup:server-array",
                          {"rows": rows, "cols": cols, 
                           "n_reps": election.n_reps,
                           "threshold": threshold},
                          time_stamp=False)

    def mix(self):
        """ Mix votes.  Information flows left to right. """
        election = self.election
        n_voters = election.n_voters
        n_reps = election.n_reps
        # replicate input to become first-column x inputs for each race & pass
        for race_id in election.race_ids:
            for k in election.k_list:
                for i in self.row_list:
                    x = self.sdb[race_id][i][0]['x']   # dict of n x's
                    self.sdb[race_id][i][0][k]['x'] = x[:]
        # generate permutations (and inverses) used in each column
        # in practice, these could be generated by row 0 server
        # and sent securely to the others in the same column.
        for race_id in election.race_ids:
            for j in range(self.cols):
                rand_name = self.sdb[race_id]['a'][j]['rand_name']
                for k in election.k_list:
                    pi = sv.random_permutation(n_voters, rand_name)
                    pi_inv = sv.inverse_permutation(pi)
                    for i in self.row_list:
                        self.sdb[race_id][i][j][k]['pi'] = pi
                        self.sdb[race_id][i][j][k]['pi_inv'] = pi_inv
        # generate obfuscation values used in each column
        # in practice, these could be generated by row 0 server
        # and sent securely to the others in the same column.
        for race in election.races:
            race_id = race.race_id
            for j in range(self.cols):
                rand_name = self.sdb[race_id]['a'][j]['rand_name']
                for k in election.k_list:
                    fuzz_list = dict()
                    for i in self.row_list:
                        fuzz_list[i] = []
                    for _ in range(self.election.n_voters):
                        share_list = sv.share(0,
                                              self.rows,
                                              self.threshold,
                                              rand_name,
                                              race.race_modulus)
                        for row, i in enumerate(self.row_list):
                            fuzz_list[i].append(share_list[row][1])
                    for i in self.row_list:
                        # note that fuzz_list[i] has length n
                        self.sdb[race_id][i][j][k]['fuzz_list'] = fuzz_list[i]
        # process columns left-to-right, mixing as you go
        for race in self.election.races:
            race_id = race.race_id
            race_modulus = race.race_modulus
            for j in range(self.cols):
                for k in election.k_list:
                    for i in self.row_list:
                        # shuffle first
                        pi = self.sdb[race_id][i][j][k]['pi'] # length n (and indep of i)
                        x = self.sdb[race_id][i][j][k]['x']   # length n
                        xp = sv.apply_permutation(pi, x)      # length n
                        # then obfuscate by adding "fuzz"
                        fuzz_list = self.sdb[race_id][i][j][k]['fuzz_list']
                        xpo = [(xp[v] + fuzz_list[v]) % race_modulus \
                               for v in range(self.election.n_voters)]
                        y = xpo
                        self.sdb[race_id][i][j][k]['y'] = y
                        # this column's y's become next column's x's.
                        # in practice would be sent via secure channels
                        if j < self.cols - 1:
                            self.sdb[race_id][i][j+1][k]['x'] = y

    def test_mix(self):
        """ Test that mixing is giving reasonable results. """
        election = self.election
        rows = self.rows
        cols = self.cols
        for race in election.races:
            race_id = race.race_id
            print("Race: ", race_id)
            for k in election.k_list:
                choice_int_list = []
                for v in range(election.n_voters):
                    share_list = \
                        [(i+1, self.sdb[race_id][i][cols-1][k]['y'][v]) \
                         for i in range(rows)]
                    choice_int = sv.lagrange(share_list, election.n_voters, \
                                             self.threshold, race.M)
                    choice_int_list.append(choice_int)
                # print("Copy:", k, choice_int_list)
                choice_str_list = [race.choice_int2str(choice_int) \
                                   for choice_int in choice_int_list]
                print("Copy:", k, choice_str_list)

