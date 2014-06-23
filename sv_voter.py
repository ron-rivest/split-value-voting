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
# import sv_election

class Voter:
    """ Implement a voter. """

    def __init__(self, election, voter_id):
        """ Initialize voter object for this election. """

        self.election = election

        assert isinstance(voter_id, str)
        self.voter_id = voter_id

        # randomness source per voter
        self.rand_name = "voter:"+voter_id
        sv.init_randomness_source(self.rand_name)

def cast_votes(election):
    """ Cast random votes for all voters for all races in simulated election.

    Of course, in a real election, choices come from voter via tablet.
    """

    cvs = dict()
    for race in election.races:
        race_id = race.race_id
        race_modulus = race.race_modulus
        cvs[race_id] = dict()

        for px_int, voter in enumerate(election.voters):
            px = election.p_list[px_int]
            rand_name = voter.rand_name
            cvs[race_id][px] = dict()

            # cast random vote (for this simulation, it's random)
            choice_str = race.random_choice()            # returns a string
            choice_int = race.choice_str2int(choice_str) # convert to integer

            # ballot_id is random hex string of desired length
            ballot_id_len = election.ballot_id_len
            ballot_id = sv.bytes2hex(sv.get_random_from_source(rand_name))
            ballot_id = ballot_id[:ballot_id_len]
            assert len(ballot_id) == election.ballot_id_len

            # secret-share choice
            n = election.server.rows
            t = election.server.threshold
            share_list = sv.share(choice_int, n, t, rand_name, race_modulus)

            # double-check that shares reconstruct to desired choice
            assert choice_int == sv.lagrange(share_list, n, t, race_modulus)
            # double-check that shares are have indices 1, 2, ..., n
            assert all([share_list[i][0] == i+1 for i in range(n)])
            # then strip off indices, since they are equal to row number + 1
            share_list = [share[1] for share in share_list]

            # save ballots on election cast vote list
            for row, x in enumerate(share_list):
                (u, v) = sv.get_sv_pair(x, rand_name, race_modulus)
                ru = sv.bytes2base64(sv.get_random_from_source(rand_name))
                rv = sv.bytes2base64(sv.get_random_from_source(rand_name))
                pair = [sv.com(u, ru), sv.com(v, rv)]
                i = election.server.row_list[row]
                vote = {"ballot_id": ballot_id, "x": x, "u": u, "v": v,
                        "ru": ru, "rv": rv, "pair": pair}
                cvs[race_id][px][i] = vote
    election.cast_votes = cvs

def distribute_cast_votes(election):
    """ Distribute (sorted) cast votes to server data structure. """
    for race_id in election.race_ids:
        for px in election.p_list:
            for i in election.server.row_list:
                vote = election.cast_votes[race_id][px][i]
                # save these values in our data structures
                # in a non-simulated real election, this would be done
                # by communicating securely from voter (or tablet) to the
                # first column of servers.
                sdbp = election.server.sdb[race_id][i][0]
                sdbp['ballot_id'][px] = vote['ballot_id']
                sdbp['x'][px] = vote['x']
                sdbp['u'][px] = vote['u']
                sdbp['v'][px] = vote['v']
                sdbp['ru'][px] = vote['ru']
                sdbp['rv'][px] = vote['rv']
                sdbp['cast_votes'][px] = vote['pair']

def post_cast_vote_commitments(election):
    """ Post cast vote commitments onto SBB. """
    cvs = election.cast_votes
    cvcs = dict()
    for race_id in election.race_ids:
        cvcs[race_id] = dict()
        for px in election.p_list:
            cvcs[race_id][px] = dict()
            cvcs[race_id][px]['pair_dict'] = dict()
            for i in election.server.row_list:
                cvcs[race_id][px]['ballot_id'] = \
                    cvs[race_id][px][i]['ballot_id']
                cvcs[race_id][px]['pair_dict'][i] = \
                    cvs[race_id][px][i]['pair']
    election.sbb.post("casting:votes",
                      {"cast_vote_dict": cvcs},
                      time_stamp=False)


