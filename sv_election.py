# sv_election.py
# python3
# Top-level code for running election with split-value method

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

# import sv
import sv_prover
import sv_server
import sv_race
import sv_sbb
import sv_tally
import sv_voter

class Election:
    """ Implements a (simulated) election. """

    def __init__(self, election_parameters):
        """ Initialize election object.

        Initialize election, where election_parameters is a dict
        with at least the following key/values:
            "election_id" is a string
            "ballot_style" is a list of (race_id, choices) pairs,
               in which
                   race_id is a string
                   choices is list consisting of
                       one string for each allowable candidate/choice name, or
                       a string "******************" of stars
                           of the maximum allowable length of a write-in
                           if write-ins are allowed.

                Example:
                  ballot_style = [("President", ("Smith", "Jones", "********"))]
                defines a ballot style with one race (for President), and
                for this race the voter may vote for Smith, for Jones, or
                may cast a write-in vote of length at most 8 characters.
            "n_voters" is the number of simulated voters
            "n_reps" is the parameter for the cut-and-choose step (n_reps replicas are made)
                     (in our paper, n_reps is called "2m")
            "n_fail" is the number of servers that may fail
            "n_leak" is the number of servers that may leak
        """

        self.election_parameters = election_parameters

        # manadatory parameters
        election_id = election_parameters["election_id"]
        ballot_style = election_parameters["ballot_style"]
        n_voters = election_parameters["n_voters"]
        n_reps = election_parameters["n_reps"]
        n_fail = election_parameters["n_fail"]
        n_leak = election_parameters["n_leak"]
        # optional parameters (with defaults)
        ballot_id_len = election_parameters.get("ballot_id_len",32)

        # check and save parameters
        assert isinstance(election_id,str) and len(election_id) > 0
        self.election_id = election_id
        assert isinstance(ballot_style,list) and len(ballot_style) > 0
        self.ballot_style = ballot_style
        assert isinstance(n_voters, int) and n_voters > 0
        self.n_voters = n_voters
        assert isinstance(n_reps, int) and n_reps > 0 and n_reps % 2 == 0
        self.n_reps = n_reps
        assert isinstance(n_fail, int) and n_fail >= 0
        assert isinstance(n_leak, int) and n_leak >= 0
        self.n_fail = n_fail
        self.n_leak = n_leak
        assert ballot_id_len > 0
        self.ballot_id_len = ballot_id_len

        # start secure bulletin board
        self.sbb = sv_sbb.SBB(election_id)
        self.sbb.post("setup:start", {"election_id": election_id})

        self.races = []
        self.race_ids = [race_id for (race_id, choices) in ballot_style]
        self.setup_races(ballot_style)
        self.voters = []
        self.setup_voters(n_voters)
        # list of cast votes
        # each of form: (race_id, ballot_id, i, x, u, v, ru, rv, pair)
        self.cast_votes = []
        self.server = sv_server.Server(self, n_fail, n_leak)
        # list of output commitments
        # each of form: (race_id, i, y, u, v, ru, rv, pair)
        self.output_commitments = []
        self.setup_keys()
        self.sbb.post("setup:finished")

    def run_election(self):
        """ Run a (simulated) election. """

        # Vote !
        for voter in self.voters:
            voter.cast_votes()
        sv_voter.sort_cast_votes(self)
        sv_voter.distribute_cast_votes(self)
        sv_voter.post_cast_votes(self)

        # Mix !
        self.server.mix()

        # Tally! 
        sv_tally.compute_tally(self)
        sv_tally.post_tally(self)
        sv_tally.print_tally(self)

        # Prove!
        sv_prover.make_proof(self)

        # Stop election and close sbb
        self.sbb.post("election:done.")
        self.sbb.close()

    def setup_races(self, ballot_style):
        """ Set up races for this election, where ballot_style is
        a list of (race_id, choices) pairs, and where
            race_id is a string
            choices is list consisting of
               one string for each allowable candidate/choice name
               a string "******************" of stars
                  of the maximum allowable length of a write-in
                  if write-ins are allowed.

        Example:
          ballot_style = [("President", ("Smith", "Jones", "********"))]
             defines a ballot style with one race (for President), and
             for this race the voter may vote for Smith, for Jones, or
             may cast a write-in vote of length at most 8 characters.
        """
        # check that race_id's are distinct:
        race_ids = [race_id for (race_id, choices) in ballot_style]
        assert len(race_ids) == len(set(race_ids))

        for (race_id, choices) in ballot_style:
            self.races.append(sv_race.Race(self, race_id, choices))

        race_list = []
        for race in self.races:
            race_list.append({"race_id": race.race_id, 
                              "choices": race.choices,
                              "race_modulus": race.race_modulus})
        self.sbb.post("setup:races",
                      {"race_list": race_list},
                      time_stamp=False)

    def setup_voters(self, n_voters):
        """ Set up election to have n_voters voters in this simulation. """
       
        assert isinstance(n_voters, int) and n_voters > 0

        for i in range(n_voters):
            voter_id = "voter:" + str(i)
            self.voters.append(sv_voter.Voter(self,voter_id))

        self.sbb.post("setup:voters", 
                      {"n_voters": n_voters},
                      time_stamp=False)
                    
        if False:
            if n_voters <= 3:
                self.sbb.post("(setup:voter_ids)", 
                              {"list": self.voters})
            else:
                self.sbb.post("(setup:voter_ids)", 
                              {"list": (self.voters[0].voter_id, "...", self.voters[-1].voter_id)},
                              time_stamp=False)

    def setup_keys(self):
        """ Set up cryptographic keys for this election simulation.

        Not done here in this simulation for simplicity.
        """
        pass
