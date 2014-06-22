# sv_verifier.py
# python3
# Code for verifier portion of an election
# This should work for simulated election, or a real election.

""" Usage: python3 sv_verifier.py election_id.sbb.txt

           where election_id.sbb.txt is the file having
           the contents of the secure bulletin board (json format).
"""

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

import json
import sv
import sys

# headers, in ordered expected in SBB file.
HEADER_LIST = ['sbb:open',
               'setup:start',
               'setup:races', 
               'setup:voters', 
               'setup:server-array',
               'setup:finished',
               'casting:votes',
               'tally:results',
               'proof:all_output_commitments',
               'proof:t_values_for_all_output_commitments',
               'proof:verifier_challenges',
               'proof:outcome_check:opened_output_commitments',
               'proof:input_check:input_openings',
               'proof:input_check:output_openings',
               'proof:input_check:pik_for_k_in_icl',
               'election:done.',
               'sbb:close']

# attributes expected for each header
ATTRIBUTES = {'sbb:open': ["election_id", "time_iso8601"],
              'setup:start': ["election_id", "time_iso8601", "about", "legend"],
              'setup:races': ["ballot_style_race_list"], 
              'setup:voters': ["n_voters"], 
              'setup:server-array': ["cols", "rows", "n_reps", "threshold"],
              'setup:finished': ["time_iso8601"],
              'casting:votes': ["cast_vote_dict"],
              'tally:results': ["election_id", "tally", "time_iso8601"],
              'proof:all_output_commitments': ["commitments"],
              'proof:t_values_for_all_output_commitments': ["t_values"],
              'proof:verifier_challenges': ["challenges", "sbb_hash"],
              'proof:outcome_check:opened_output_commitments': ["opened_commitments"],
              'proof:input_check:input_openings': ["opened_commitments"],
              'proof:input_check:output_openings': ["opened_commitments"],
              'proof:input_check:pik_for_k_in_icl': ["list"], 
              'election:done.': ["time_iso8601", "election_id"],
              'sbb:close': ["time_iso8601"]
}

def verify(sbb_filename):
    """ Perform all possible verifications on the given file. """
    
    assert isinstance(sbb_filename,str) and len(sbb_filename) > 0
    
    sbb_file = open(sbb_filename,"r")
    sbb = json.load(sbb_file)

    db = dict()          # master database for storing stuff

    sbb_dict = check_headers(sbb)
    print_sizes(sbb_dict)
    check_attributes(sbb_dict)
    check_monotonic_time(sbb)
    check_consistent_election_ids(sbb)
    read_races(sbb_dict, db)
    read_n_voters(sbb_dict, db)
    read_rows_cols_n_reps_threshold(sbb_dict, db)
    read_cast_votes(sbb_dict, db)
    read_tally(sbb_dict, db)
    read_output_commitments(sbb_dict, db)
    read_t_values(sbb_dict, db)
    read_verifier_challenges(sbb_dict, sbb, db)
    check_inputs(sbb_dict, db)
    check_opened_output_commitments(sbb_dict, db)
    check_opened_output_commitment_tallies(sbb_dict, db)
    print("all verifications (as implemented so far) passed!!")
    
def check_headers(sbb):
    """ Check that expected headers are present, and return sbb_dict
        mapping headers to dict's.
    """
    header_list = []
    sbb_dict = dict()
    for item in sbb:
        assert isinstance(item, list) and len(item) > 0
        item_header = item[0]
        assert isinstance(item_header, str) and len(item_header) > 0
        header_list.append(item_header)
        item_dict = item[1]
        assert isinstance(item_dict, dict)
        sbb_dict[item_header] = item_dict
    assert header_list == HEADER_LIST
    print("check_headers: passed.")
    return sbb_dict

def print_sizes(sbb_dict):
    """ Debugging tool to understand where sbb size is, mostly. """
    print("print_sizes: (FYI) sizes of components of sbb:")
    for item_header in HEADER_LIST:
        item_dict = sbb_dict[item_header]
        item_dict_str = json.dumps(item_dict, sort_keys=True, indent=2)
        print("   ", "%11d"%len(item_dict_str), item_header)

def check_attributes(sbb_dict):
    """ Check that each item in sbb has precisely expected attributes. """
    for item_header in sbb_dict.keys():
        item_dict = sbb_dict[item_header]
        assert set(ATTRIBUTES[item_header]) == set(item_dict.keys()),\
            item_header
    print("check_attributes: passed.")

def check_monotonic_time(sbb):
    """ Check that time stamps are non-decreasing. """
    last_item_time = None
    for item in sbb:
        item_dict = item[1]
        if "time_iso8601" in item_dict:
            item_time = item_dict["time_iso8601"]
            assert last_item_time == None or \
                item_time >= last_item_time
            last_item_time = item_time
    print("check_monotonic_time: passed.")

def check_consistent_election_ids(sbb):
    """ Check that all election_id's are equal. """
    election_id = None
    for item in sbb:
        item_dict = item[1]
        if "election_id" in item_dict:
            item_election_id = item_dict["election_id"]
            assert election_id == None or \
                item_election_id == election_id
            election_id = item_election_id
    assert election_id
    print("check_consistent_election_ids: passed.")

def read_races(sbb_dict, db):
    """ Read races item and gather info into db """
    races = dict()     # maps race_id's to dicts
    for race_dict in sbb_dict["setup:races"]["ballot_style_race_list"]:
        assert set(race_dict.keys()) == \
            set(["choices", "race_id", "race_modulus"])
        race_id = race_dict["race_id"]
        races[race_id] = race_dict
    db["races"] = races
    db["race_ids"] = races.keys()
    print("read_races: successful.")

def read_n_voters(sbb_dict, db):
    """ Read setup:voters item and save n_voters into db. """
    n_voters = sbb_dict["setup:voters"]["n_voters"]
    assert isinstance(n_voters, int) and n_voters > 0
    db["n_voters"] = n_voters
    print("read_n_voters: successful.")

def read_rows_cols_n_reps_threshold(sbb_dict, db):
    """ Read setup:server-array to extract rows/cols/n_reps into db. """
    rows = sbb_dict["setup:server-array"]["rows"]
    cols = sbb_dict["setup:server-array"]["cols"]
    n_reps = sbb_dict["setup:server-array"]["n_reps"]
    threshold = sbb_dict["setup:server-array"]["threshold"]
    assert isinstance(rows, int) and rows > 0
    assert isinstance(cols, int) and cols > 0
    assert isinstance(n_reps, int) and n_reps > 0
    assert isinstance(threshold, int) and threshold > 0
    db["rows"] = rows
    db["cols"] = cols
    db["n_reps"] = n_reps
    db["threshold"] = threshold
    assert rows < 27
    db["row_list"] = 'abcdefghijklmnopqrstuvwxyz'[:rows]
    assert n_reps < 27
    db["k_list"] = [c for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'[:n_reps]]
    print("read_rows_cols_n_reps_threshold: successful.")

def read_cast_votes(sbb_dict, db):
    """ Read casting:votes for cast votes and extract them into db. 

        Assumes that every voter votes in every race (could be weakened).
    """
    cast_vote_dict = sbb_dict["casting:votes"]["cast_vote_dict"]
    assert set(db["races"].keys()) == set(cast_vote_dict.keys())
    ballot_id_dict = dict()
    ballot_id_list = list()
    for race_id in db["races"].keys():
        ballot_id_dict[race_id] = []
        cast_vote_race = cast_vote_dict[race_id]
        assert isinstance(cast_vote_race, dict)
        assert len(cast_vote_race) == db["n_voters"]
        for p in cast_vote_race.keys():
            cast_vote = cast_vote_race[p]
            assert set(cast_vote.keys()) == set(["ballot_id", "pair_dict"])
            ballot_id = cast_vote["ballot_id"]
            assert isinstance(ballot_id, str)
            ballot_id_dict[race_id].append(ballot_id)
            ballot_id_list.append(ballot_id)

            assert isinstance(cast_vote["pair_dict"], dict)
            pair_dict = cast_vote["pair_dict"]
            assert len(pair_dict) == db["rows"]
            for i in pair_dict:
                pair = pair_dict[i]
                assert isinstance(pair, list)
                assert len(pair) == 2
                assert isinstance(pair[0], str)
                assert isinstance(pair[1], str)
    assert len(set(ballot_id_list)) == len(ballot_id_list)   # ballot id's distinct
    db["ballot_id_dict"] = ballot_id_dict
    db["cast_vote_dict"] = cast_vote_dict
    print("read_cast_votes: successful.")

def read_tally(sbb_dict, db):
    """ Read tally from tally:results and save into db. """
    tally = sbb_dict["tally:results"]["tally"]
    assert isinstance(tally, dict)
    assert set(tally.keys()) == set(db["races"].keys())
    for race_id in tally.keys():
        assert len(tally[race_id]) > 0
        for key in tally[race_id]:
            assert isinstance(key, str)
            assert isinstance(tally[race_id][key], int)
    db["tally"] = tally
    print("read_tally: successful.")

def read_output_commitments(sbb_dict, db):
    """ Read output commitments from proof:all_output_commitments
    and put results into db.
    """
    coms = sbb_dict["proof:all_output_commitments"]["commitments"]
    assert isinstance(coms, dict)
    assert set(coms.keys()) == set(db["race_ids"])
    for race_id in db["race_ids"]:
        kiys = coms[race_id]
        assert isinstance(kiys, dict)
        assert set(kiys.keys()) == set(db["k_list"])
        for k in db["k_list"]:
            iys = kiys[k]
            assert isinstance(iys, dict)
            assert isinstance(com["pair_list"], list)
            pair_list = com["pair_list"]
            assert len(pair_list) == db["rows"]
            for pair in pair_list:
                assert isinstance(pair, list)
                assert len(pair) == 2
                assert isinstance(pair[0], str)
                assert isinstance(pair[1], str)        
    db["output_commitments"] = coms
    print("read_output_commitments: successful.")

def read_t_values(sbb_dict, db):
    """ Read t values from proof:t_values_for_all_output_commitments, and
        save them in db.
    """
    t_values = sbb_dict["proof:t_values_for_all_output_commitments"]["list"]
    assert len(t_values) == len(db["output_commitments"]) * db["rows"]
    for t_value in t_values:
        assert isinstance(t_value, dict)
        assert set(t_value.keys()) == set(["i", "ix", "k", "race_id", "tu", "tv"])
        i = t_value["i"]
        assert isinstance(i, int) and 0 <= i < db["rows"]
        ix = t_value["ix"]
        assert isinstance(ix, int) and 0 <= ix < db["n_voters"]
        k = t_value["k"]
        assert isinstance(k, int) and 0 <= k < db["n_reps"]
        race_id = t_value["race_id"]
        assert isinstance(race_id, str) and race_id in db["races"]
        tu = t_value["tu"]
        assert isinstance(tu, int) and 0 <= tu < db["races"][race_id]["race_modulus"]
        tv = t_value["tv"]
        assert isinstance(tv, int) and 0 <= tv < db["races"][race_id]["race_modulus"]
    db["t_values"] = t_values
    print("read_t_values: successful.")

def read_verifier_challenges(sbb_dict, sbb, db):
    """ Read verifier challenges from proof:verifier_challenges and save into db. """
    challenges = sbb_dict['proof:verifier_challenges']['challenges']
    assert isinstance(challenges, dict)
    assert set(challenges.keys()) == set(["icl", "leftright", "opl"])
    icl = challenges["icl"]
    assert isinstance(icl, list)
    assert len(icl) == db["n_reps"] // 2
    assert set(icl).issubset(range(db["n_reps"]))
    opl = challenges["opl"]
    assert isinstance(opl, list)
    assert len(opl) == db["n_reps"] // 2
    assert set(opl).issubset(range(db["n_reps"]))
    assert set(icl).isdisjoint(set(opl))
    db["icl"] = icl
    db["opl"] = opl
    leftright = challenges["leftright"]
    assert isinstance(leftright, dict)
    assert leftright.keys() == db["races"].keys()
    for race_id in leftright.keys():
        lr_list = leftright[race_id]
        assert len(lr_list) == db["n_voters"]
        for lr in lr_list:
            assert lr == "left" or lr == "right"
    db["leftright"] = leftright
    # now check that icl, opl, and leftright are consistent with sbb_hash
    # see make_verifier_challenges in sv_prover.py
    rand_name = "verifier_challenges"
    sbb_hash = sbb_dict["proof:verifier_challenges"]["sbb_hash"]
    stop_before_header = "proof:verifier_challenges"
    sbb_hash2 = sv.bytes2hex(hash_sbb(sbb, stop_before_header))
    assert sbb_hash2 == sbb_hash
    sv.init_randomness_source(rand_name, sv.hex2bytes(sbb_hash))
    pi = sv.random_permutation(db["n_reps"], rand_name)
    icl2 = sorted(pi[:db["n_reps"]//2])
    opl2 = sorted(pi[db["n_reps"]//2:])
    assert icl2 == icl
    assert opl2 == opl
    leftright2 = make_left_right_challenges(rand_name, db)
    assert leftright2 == leftright
    print("read_verifier_challenges: successful.")

def make_left_right_challenges(rand_name, db):
    """ make dict with a list of n_voters left/right challenges for each race.

    Result per race is a list of True/False values of length n_voters (True = left).
    (This routine copied from sv_prover.py.)
    This is recomputed here to check consistency with hash of sbb.
    """
    leftright_dict = dict()
    # sorting needed in next line else result depends on enumeration order
    # (sorting is also done is sv_prover.py)
    for race_id in sorted(db["races"]):
        leftright = ["left" if bool(sv.get_random_from_source(rand_name, modulus=2))\
                     else "right"\
                     for i in range(db["n_voters"])]
        leftright_dict[race_id] = leftright
    return leftright_dict

def hash_sbb(sbb, stop_before_header):
    """ Return a (tweaked) hash of the sbb contents, including
        all items up to (but not including) the item with header
        equal to stop_before_header.
        
        (Copied from sv_prover.py)
    """
    sbb_trunc = []
    for item in sbb:
        if item[0] == stop_before_header:
            break
        else:
            sbb_trunc.append(item)
    sbb_trunc_str = json.dumps(sbb_trunc, sort_keys=True, indent=2)
    hash_tweak = 2
    return sv.hash(sbb_trunc_str, hash_tweak)

def check_opened_output_commitments(sbb_dict, db):
    """ Check that opened output commitments are opened properly. """
    opened_coms = \
        sbb_dict["proof:outcome_check:opened_output_commitments"]["opened_commitments"]
    for com in opened_coms:
        assert isinstance(com, dict)
        assert set(com.keys()) == \
            set(["i", "iy", "k", "pair", "race_id", "ru", "rv", "u", "v", "y"])
        i = com["i"]
        assert isinstance(i, int) and 0 <= i < db["rows"]
        iy = com["iy"]
        assert isinstance(iy, int) and 0 <= iy < db["n_voters"]
        k = com["k"]
        assert isinstance(k, int) and 0 <= k < db["n_reps"]
        assert k in db["opl"]
        pair = com["pair"]
        assert len(pair) == 2
        assert isinstance(pair[0], str)
        assert isinstance(pair[1], str)
        race_id = com["race_id"]
        assert isinstance(race_id, str) and race_id in db["races"]
        ru = com["ru"]
        assert isinstance(ru, str)
        rv = com["rv"]
        assert isinstance(rv, str)
        u = com["u"]
        assert isinstance(u, int) and 0 <= u < db["races"][race_id]["race_modulus"]
        v = com["v"]
        assert isinstance(v, int) and 0 <= v < db["races"][race_id]["race_modulus"]
        y = com['y']
        assert isinstance(y, int) and 0 <= y < db["races"][race_id]["race_modulus"]
        assert y == (u+v) % db["races"][race_id]["race_modulus"]
        assert pair[0] == sv.com(u, ru)
        assert pair[1] == sv.com(v, rv)
    print("check_opened_output_commitments: passed.")

def check_opened_output_commitment_tallies(sbb_dict, db):
    """ Check that for each k, the opened output commitments lagranage
        and tally to values given in tally.

        Note that output_commitments are in sbb in sorted order:
        by  race_id, k, iy, i, ...
        (see sv_prover.sort_output_commitments)
    """
    opened_coms = \
        sbb_dict["proof:outcome_check:opened_output_commitments"]["opened_commitments"]
    index = dict()
    for com in opened_coms:
        race_id = com["race_id"]
        k = com["k"]
        iy = com["iy"]
        i = com["i"]
        index[(race_id, k, iy, i)] = com
    for k in db["opl"]:
        # verify tally for this k
        tally_k = dict()
        for race_id in db["races"].keys():
            tally_k[race_id] = dict()  # choices to counts
            for iy in range(db["n_voters"]):
                share_list = []
                for i in range(db["rows"]):
                    com = index[(race_id, k, iy, i)]
                    share_list.append((i+1,com["y"]))
                w = sv.lagrange(share_list, 
                                db["rows"],
                                db["threshold"],
                                db["races"][race_id]["race_modulus"])
                # convert w back to string version of choice
                # see sv_race.choice_int2str
                choice_bytes = sv.int2bytes(w)
                choice_str = choice_bytes.decode()
                # assert self.is_valid_choice(choice_str)
                # print(race_id, k, iy, choice_str)
                cnt = tally_k[race_id].get(choice_str,0)
                tally_k[race_id][choice_str] = cnt + 1
        # print(tally_k)
        assert tally_k == db["tally"]
    print("check_opened_output_commitment_tallies: passed.")

def check_inputs(sbb_dict, db):
    """ Do all input checks.
        Check that t-values are consistent with opened inputs and
        opened outputs, for k in icl.  Also check that lagrange
        of t-value pairs for a given voter yields (t,-t).
    """
    check_inputs_pik(sbb_dict, db)
    # need to check t values and outputs corresponding to inputs

def check_inputs_pik(sbb_dict, db):
    """ Check that piks look OK. """
    pik_list = sbb_dict["proof:input_check:pik_for_k_in_icl"]["list"]
    for item in pik_list:
        assert isinstance(item, dict)
        assert set(item.keys()) == set(["race_id", "k", "pik"])
        assert item["race_id"] in db["races"]
        k = item["k"]
        assert isinstance(k, int) and 0 <= k < db["n_reps"]
        pik = item["pik"]
        assert sorted(pik) == list(range(db["n_voters"]))

def check_inputs_input_openings(sbb_dict, db):
    """ Check input openings used for testing consistency with output openings. """
    iopenings = sbb_dict["proof:input_check:input_openings"]
    

def check_inputs_output_openings(sbb_dict, db):
    """ Check output openings used for consistency with input openings. """

def check_inputs_t_value(sbb_dict, db):
    # now check that t-values are correct for halfs that are opened.
    for race_id in db["races"]:
        leftright = sbb_dict['proof:verifier_challenges']\
                    ['challenges']['leftright'][race_id] # same for all i
        pik_list["proof:pik_for_k_in_icl"]["list"]
        for k in db["icl"]:
            pik = None
            for item in pik_list:
                if item["k"] == k:
                    pik = item["pik"]
            assert pik is not None
            for iy in range(db["n_voters"]):
                ix = pik[iy]
                lr = leftright[ix]        # and not iy
                assert lr == "left" or lr == "right"
                # find input commitment
                icom = db["cast_votes"][ix]
    "TBD"

