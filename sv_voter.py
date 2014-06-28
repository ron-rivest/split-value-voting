# sv_voter.py
# python3
# Ronald L. Rivest
# 2014-06-26

""" Prototype code implementing voter portion of split-value voting method,
    including the casting of votes.
"""

# MIT open-source license.
# (See https://github.com/ron-rivest/split-value-voting.git)

import sv

class Voter:
    """ Implement a voter. """

    def __init__(self, election, voter_id, px):
        """ Initialize voter object for this election.

            Here voter_id is a string identifying the voter, and
            px is a "position identifier": 'p0', 'p1', ...
        """

        self.election = election

        assert isinstance(voter_id, str)
        self.voter_id = voter_id
        self.px = px

        # randomness source per voter
        self.rand_name = "voter:"+voter_id
        sv.init_randomness_source(self.rand_name)

        self.receipts = dict()  # maps ballot_id to hash value of receipt

    def cast_vote(self, race):
        """ Cast random vote for this voter for this race in simulated election.

        Of course, in a real election, choices come from voter via tablet.
        """

        election = self.election
        cvs = election.cast_votes
        race_id = race.race_id
        race_modulus = race.race_modulus
        rand_name = self.rand_name
        px = self.px

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

        # save ballots on election data structure
        for row, x in enumerate(share_list):
            (u, v) = sv.get_sv_pair(x, rand_name, race_modulus)
            ru = sv.bytes2base64(sv.get_random_from_source(rand_name))
            rv = sv.bytes2base64(sv.get_random_from_source(rand_name))
            cu = sv.com(u, ru)
            cv = sv.com(v, rv)
            i = election.server.row_list[row]
            vote = {"ballot_id": ballot_id, "x": x, "u": u, "v": v,
                    "ru": ru, "rv": rv, "cu": cu, "cv": cv}
            cvs[race_id][px][i] = vote

        # compute voter receipt as hash of her ballot_id and commitments
        # note that voter gets a receipt for each race she votes in
        receipt_data = [ballot_id]
        d = dict()
        for i in election.server.row_list:
            cu = cvs[race_id][px][i]['cu']
            cv = cvs[race_id][px][i]['cv']
            d[i] = {'cu': cu, 'cv': cv}
        receipt_data.append(d)
        receipt_data_str = sv.dumps(receipt_data)
        receipt_hash = sv.bytes2base64(sv.secure_hash(receipt_data_str))
        self.receipts[ballot_id] = {'race_id': race_id,
                                    'hash': receipt_hash}



