# sv_voter.py
# python3
# Prototype code implementing voter portion of split-value voting method
# This code is meant to be pedagogic and illustrative of main concepts;
# many details would need adjustment or filling in for a final implementation.
# This code only considers a one race election.
# Ronald L. Rivest
# 2014-06-14

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

import sv
import sv_election

class Voter:
    """ Implement a voter. """

    def __init__(self, election, voter_id):
        """ Initialize voter object for this election. """

        assert isinstance(election, sv_election.Election)
        self.election = election

        assert isinstance(voter_id, str)
        self.voter_id = voter_id

        # randomness source per voter
        self.rand_name = "voter:"+voter_id
        sv.init_randomness_source(self.rand_name)

    def cast_votes(self):
        """ Cast random votes for voter for all races in simulated election.

        Of course, in a real election, choices come from voter via tablet.
        """

        rand_name = self.rand_name

        for race in self.election.races:
            race_id = race.race_id
            race_modulus = race.race_modulus

            # cast random vote (for this simulation, it's random)
            choice_str = race.random_choice()            # returns a string
            choice_int = race.choice_str2int(choice_str) # convert to integer

            # ballot_id is random hex string of desired length
            ballot_id_len = self.election.ballot_id_len
            ballot_id = sv.bytes2hex(sv.get_random_from_source(rand_name))
            ballot_id = ballot_id[:ballot_id_len]
            assert len(ballot_id) == self.election.ballot_id_len

            # secret-share choice
            n = self.election.server.rows
            t = self.election.server.threshold
            share_list = sv.share(choice_int, n, t, rand_name, race_modulus)

            # double-check that shares reconstruct to desired choice
            assert choice_int == sv.lagrange(share_list, n, t, race_modulus)
            # double-check that shares are have indices 1, 2, ..., n
            assert all([share_list[i][0] == i+1 for i in range(n)])
            # then strip off indices, since they are equal to row number + 1
            share_list = [share[1] for share in share_list]

            # save ballots on election cast vote list
            for i, x in enumerate(share_list):
                (u, v) = sv.get_sv_pair(x, rand_name, race_modulus)
                ru = sv.bytes2hex(sv.get_random_from_source(rand_name))
                rv = sv.bytes2hex(sv.get_random_from_source(rand_name))
                pair = [sv.com(u, ru), sv.com(v, rv)]
                vote = (race_id, ballot_id, i, x, u, v, ru, rv, pair)
                self.election.cast_votes.append(vote)

def sort_cast_votes(election):
    """ sort votes into order by race_id, ballot_id, i, x, ...

    In a real election, this means that cast votes are accumulated
    somewhere (tally server), then sorted before being distributed
    to the first column of mix servers
    """
    election.cast_votes = sorted(election.cast_votes)

def distribute_cast_votes(election):
    """ Distribute (sorted) cast votes to server data structure. """
    for race_id, ballot_id, i, x, u, v, ru, rv, pair in election.cast_votes:
        # save these values in our data structures
        # in a non-simulated real election, this would be done by communicating
        # securely from voter (or tablet) to the first column of servers.
        sdbp = election.server.sdb[race_id][i][0]
        sdbp['ballot_id'].append(ballot_id)
        sdbp['x'].append(x)
        sdbp['u'].append(u)
        sdbp['v'].append(v)
        sdbp['ru'].append(ru)
        sdbp['rv'].append(rv)
        sdbp['cast_votes'].append(pair)

def post_cast_votes(election):
    """ Post cast votes onto SBB. """
    cast_vote_dict = dict()
    for race in election.races:
        race_id = race.race_id
        cast_vote_dict[race_id] = []
    last_ballot_id = None
    pair_list_for_ballot_id = []
    for race_id, ballot_id, i, x, u, v, ru, rv, pair in election.cast_votes:
        if last_ballot_id == None:
            pair_list_for_ballot_id.append(pair)
            last_ballot_id = ballot_id
            last_race_id = race_id
        elif ballot_id == last_ballot_id:
            pair_list_for_ballot_id.append(pair)
        else:
            cast_vote_dict[last_race_id].append({"ballot_id": last_ballot_id,
                                            "pair_list": pair_list_for_ballot_id})
            last_race_id = race_id
            last_ballot_id = ballot_id
            pair_list_for_ballot_id = [pair]
    if pair_list_for_ballot_id:
        cast_vote_dict[last_race_id].append({"ballot_id": last_ballot_id,
                                             "pair_list": pair_list_for_ballot_id})
    election.sbb.post("casting:votes",
                      {"cast_vote_dict": cast_vote_dict},
                      time_stamp=False)


