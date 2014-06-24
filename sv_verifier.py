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
MIT_license = \
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
               'proof:outcome_check',
               'proof:input_check:input_openings',
               'proof:input_check:output_openings',
               'proof:input_check:pik_for_k_in_icl',
               'election:done.',
               'sbb:close']

# attributes expected for each header
ATTRIBUTES = {'sbb:open': ['election_id', 'time_iso8601'],
              'setup:start': ['election_id', 'time_iso8601',
                              'about', 'legend'],
              'setup:races': ['ballot_style_race_dict'],
              'setup:voters': ['n_voters', 'ballot_id_len'],
              'setup:server-array':
                  ['cols', 'rows', 'n_reps', 'threshold', 'json_indent'],
              'setup:finished': ['time_iso8601'],
              'casting:votes': ['cast_vote_dict'],
              'tally:results': ['election_id', 'tally', 'time_iso8601'],
              'proof:all_output_commitments': ['commitments'],
              'proof:t_values_for_all_output_commitments': ['t_values'],
              'proof:verifier_challenges': ['challenges', 'sbb_hash'],
              'proof:outcome_check':
                  ['opened_output_commitments'],
              'proof:input_check:input_openings': ['opened_commitments'],
              'proof:input_check:output_openings': ['opened_commitments'],
              'proof:input_check:pik_for_k_in_icl': ['pik_dict'],
              'election:done.': ['time_iso8601', 'election_id'],
              'sbb:close': ['time_iso8601']
             }

def has_keys(d, keys):
    """ Return True if dict d has given set of keys.

    Here keys could be a list or a set.
    """
    if not isinstance(keys, set):
        keys = set(keys)
    return set(d.keys()) == keys

def isdict(d, keys=None):
    """ Return True if d is a dict (optionally with right set of keys)

    Here keys could be a list or a set.
    """
    if not isinstance(d, dict):
        return False
    return isinstance(d, dict) and (keys == None or has_keys(d, keys))

def verify(sbb_filename):
    """ Perform all possible verifications on the given file. """

    assert isinstance(sbb_filename, str) and len(sbb_filename) > 0

    sbb_file = open(sbb_filename, 'r')
    sbb = json.load(sbb_file)

    db = dict()          # master database for storing stuff

    sbb_dict = check_headers(sbb)
    print_sizes(sbb_dict)
    check_attributes(sbb_dict)
    check_monotonic_time(sbb)
    check_consistent_election_ids(sbb)
    read_races(sbb_dict, db)
    read_n_voters(sbb_dict, db)
    read_rows_cols_n_reps_threshold_indent(sbb_dict, db)
    read_cast_votes(sbb_dict, db)
    read_tally(sbb_dict, db)
    read_output_commitments(sbb_dict, db)
    read_t_values(sbb_dict, db)
    read_verifier_challenges(sbb_dict, sbb, db)
    check_inputs(sbb_dict, db)
    check_opened_output_commitments(sbb_dict, db)
    check_opened_output_commitment_tallies(sbb_dict, db)
    print('all verifications (as implemented so far) passed!!')

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
        assert isdict(item_dict)
        sbb_dict[item_header] = item_dict
    assert header_list == HEADER_LIST
    print('check_headers: passed.')
    return sbb_dict

def print_sizes(sbb_dict):
    """ Debugging tool to understand where sbb size is, mostly. """
    print('print_sizes: (FYI) sizes of components of sbb:')
    for item_header in HEADER_LIST:
        item_dict = sbb_dict[item_header]
        item_dict_str = json.dumps(item_dict, sort_keys=True, indent=2)
        print('   ', '%11d'%len(item_dict_str), item_header)

def check_attributes(sbb_dict):
    """ Check that each item in sbb has precisely expected attributes. """
    for item_header in sbb_dict.keys():
        item_dict = sbb_dict[item_header]
        assert has_keys(item_dict, ATTRIBUTES[item_header]), item_header
    print('check_attributes: passed.')

def check_monotonic_time(sbb):
    """ Check that time stamps are non-decreasing. """
    last_item_time = None
    for item in sbb:
        item_dict = item[1]
        if 'time_iso8601' in item_dict:
            item_time = item_dict['time_iso8601']
            assert last_item_time == None or \
                item_time >= last_item_time
            last_item_time = item_time
    print('check_monotonic_time: passed.')

def check_consistent_election_ids(sbb):
    """ Check that all election_id's are equal. """
    election_id = None
    for item in sbb:
        item_dict = item[1]
        if 'election_id' in item_dict:
            item_election_id = item_dict['election_id']
            assert election_id == None or \
                item_election_id == election_id
            election_id = item_election_id
    assert election_id
    print('check_consistent_election_ids: passed.')

def read_races(sbb_dict, db):
    """ Read races item and gather info into db """
    races = sbb_dict['setup:races']['ballot_style_race_dict']
    for race_id in sbb_dict['setup:races']['ballot_style_race_dict']:
        race_dict = sbb_dict['setup:races']['ballot_style_race_dict'][race_id]
        assert has_keys(race_dict, ['choices', 'race_modulus'])
    db['races'] = races
    db['race_ids'] = races.keys()
    print('read_races: successful.')

def read_n_voters(sbb_dict, db):
    """ Read setup:voters item and save n_voters into db. """
    n_voters = sbb_dict['setup:voters']['n_voters']
    assert isinstance(n_voters, int) and n_voters > 0
    db['n_voters'] = n_voters
    db['p_list'] = sv.p_list(n_voters)
    ballot_id_len = sbb_dict['setup:voters']['ballot_id_len']
    assert isinstance(ballot_id_len, int)
    assert ballot_id_len > 0
    print('read_n_voters: successful.')

def read_rows_cols_n_reps_threshold_indent(sbb_dict, db):
    """ Read setup:server-array to extract rows/cols/n_reps into db. """
    sbbd = sbb_dict['setup:server-array']
    rows = sbbd['rows']
    cols = sbbd['cols']
    n_reps = sbbd['n_reps']
    threshold = sbbd['threshold']
    json_indent = sbbd['json_indent']
    assert isinstance(rows, int) and rows > 0
    assert isinstance(cols, int) and cols > 0
    assert isinstance(n_reps, int) and n_reps > 0
    assert isinstance(threshold, int) and threshold > 0
    db['rows'] = rows
    assert rows < 27
    db['row_list'] = sv.row_list(rows)
    db['cols'] = cols
    db['n_reps'] = n_reps
    db['threshold'] = threshold
    assert n_reps < 27
    db['k_list'] = sv.k_list(n_reps)
    assert isinstance(json_indent, int)
    assert json_indent >= 0
    db['json_indent'] = json_indent
    print('read_rows_cols_n_reps_threshold: successful.')

def read_cast_votes(sbb_dict, db):
    """ Read casting:votes for cast votes and extract them into db.

        Assumes that every voter votes in every race (could be weakened).
    """
    cast_vote_dict = sbb_dict['casting:votes']['cast_vote_dict']
    assert isdict(db['races'], cast_vote_dict.keys())
    ballot_id_dict = dict()
    ballot_id_list = list()
    for race_id in db['races'].keys():
        ballot_id_dict[race_id] = []
        cast_vote_race = cast_vote_dict[race_id]
        assert isdict(cast_vote_race)
        assert len(cast_vote_race) == db['n_voters']
        for p in cast_vote_race.keys():
            cast_vote_race_p = cast_vote_race[p]
            assert isdict(cast_vote_race_p, db['row_list'])
            for i in db['row_list']:
                assert isdict(cast_vote_race_p[i], ['ballot_id', 'cu', 'cv'])
                if i == db['row_list'][0]:
                    ballot_id = cast_vote_race_p[i]['ballot_id']
                    assert isinstance(ballot_id, str)
                    ballot_id_dict[race_id].append(ballot_id)
                    ballot_id_list.append(ballot_id)
                else:
                    assert ballot_id == cast_vote_race_p[i]['ballot_id']
                cu = cast_vote_race_p[i]['cu']
                assert isinstance(cu, str)
                cv = cast_vote_race_p[i]['cv']
                assert isinstance(cv, str)
    # next line checks that ballot id's are distinct
    assert len(set(ballot_id_list)) == len(ballot_id_list)
    db['ballot_id_dict'] = ballot_id_dict
    db['cast_vote_dict'] = cast_vote_dict
    print('read_cast_votes: successful.')

def read_tally(sbb_dict, db):
    """ Read tally from tally:results and save into db. """
    tally = sbb_dict['tally:results']['tally']
    assert isdict(tally, db['races'])
    for race_id in tally.keys():
        assert len(tally[race_id]) > 0
        for key in tally[race_id]:
            assert isinstance(key, str)
            assert isinstance(tally[race_id][key], int)
    db['tally'] = tally
    print('read_tally: successful.')

def read_output_commitments(sbb_dict, db):
    """ Read output commitments from proof:all_output_commitments
    and put results into db.
    """
    coms = sbb_dict['proof:all_output_commitments']['commitments']
    assert isdict(coms, db['race_ids'])
    for race_id in db['race_ids']:
        assert isdict(coms[race_id], db['k_list'])
        for k in db['k_list']:
            assert isdict(coms[race_id][k], db['p_list'])
            for p in db['p_list']:
                assert isdict(coms[race_id][k][p], db['row_list'])
                for i in db['row_list']:
                    assert isdict(coms[race_id][k][p][i], ['cu', 'cv'])
                    cu = coms[race_id][k][p][i]['cu']
                    cv = coms[race_id][k][p][i]['cv']
                    assert isinstance(cu, str)
                    assert isinstance(cv, str)
    db['output_commitments'] = coms
    print('read_output_commitments: successful.')

def read_t_values(sbb_dict, db):
    """ Read t values from proof:t_values_for_all_output_commitments, and
        save them in db.
    """
    ts = sbb_dict['proof:t_values_for_all_output_commitments']['t_values']
    assert isdict(ts, db['race_ids'])
    for race_id in db['race_ids']:
        assert isdict(ts[race_id], db['k_list'])
        for k in db['k_list']:
            assert isdict(ts[race_id][k], db['p_list'])
            for p in db['p_list']:
                assert isdict(ts[race_id][k][p], db['row_list'])
                for i in db['row_list']:
                    assert isdict(ts[race_id][k][p][i], ['tu', 'tv'])
                    tu = ts[race_id][k][p][i]['tu']
                    tv = ts[race_id][k][p][i]['tv']
                    assert isinstance(tu, int)
                    assert isinstance(tv, int)
                    assert 0 <= tu < db['races'][race_id]['race_modulus']
                    assert 0 <= tv < db['races'][race_id]['race_modulus']
    db['t_values'] = ts
    print('read_t_values: successful.')

def read_verifier_challenges(sbb_dict, sbb, db):
    """ Read verifier challenges from proof:verifier_challenges; save into db.
    """
    chs = sbb_dict['proof:verifier_challenges']['challenges']
    assert isdict(chs, ['cut', 'leftright'])
    assert isdict(chs['cut'], ['icl', 'opl'])
    icl = chs['cut']['icl']
    assert isinstance(icl, list)
    assert len(icl) == db['n_reps'] // 2
    assert set(icl).issubset(db['k_list'])
    opl = chs['cut']['opl']
    assert isinstance(opl, list)
    assert len(opl) == db['n_reps'] // 2
    assert set(opl).issubset(db['k_list'])
    assert set(icl).isdisjoint(set(opl))
    db['icl'] = icl
    db['opl'] = opl
    leftright = chs['leftright']
    assert isdict(leftright, db['race_ids'])
    for race_id in leftright.keys():
        lr_dict = leftright[race_id]
        assert set(lr_dict.keys()) == set(db['p_list'])
        for p in db['p_list']:
            lr = lr_dict[p]
            assert lr == 'left' or lr == 'right'
    db['leftright'] = leftright
    # now check that icl, opl, and leftright are consistent with sbb_hash
    # see make_verifier_challenges in sv_prover.py
    rand_name = 'verifier_challenges'
    sbb_hash = sbb_dict['proof:verifier_challenges']['sbb_hash']
    stop_before_header = 'proof:verifier_challenges'
    sbb_hash2 = sv.bytes2hex(hash_sbb(sbb,
                                      stop_before_header,
                                      db['json_indent']))
    assert sbb_hash2 == sbb_hash
    sv.init_randomness_source(rand_name, sv.hex2bytes(sbb_hash))
    pi = sv.random_permutation(db['n_reps'], rand_name)
    m = db['n_reps'] // 2
    pi = [pi[i] for i in range(2*m)]
    icl2 = [db['k_list'][i] for i in sorted(pi[:m])]
    opl2 = [db['k_list'][i] for i in sorted(pi[m:])]
    assert icl2 == icl
    assert opl2 == opl
    leftright2 = make_left_right_challenges(rand_name, db)
    assert leftright2 == leftright
    print('read_verifier_challenges: successful.')

def make_left_right_challenges(rand_name, db):
    """ make dict with a list of n_voters left/right challenges for each race.

    Result per race is a list of left/right values of length n_voters.
    (This routine copied from sv_prover.py.)
    This is recomputed here to check consistency with hash of sbb.
    """
    leftright_dict = dict()
    # sorting needed in next line else result depends on enumeration order
    # (sorting is also done is sv_prover.py)
    for race_id in sorted(db['races']):
        leftright = dict()
        for p in db['p_list']:
            leftright[p] = 'left'\
                           if bool(sv.get_random_from_source(rand_name,
                                                             modulus=2))\
                           else 'right'
        leftright_dict[race_id] = leftright
    return leftright_dict

def hash_sbb(sbb, stop_before_header, json_indent):
    """ Return a (tweaked) hash of the sbb contents, including
        all items up to (but not including) the item with header
        equal to stop_before_header. (Copied from sv_prover.py)
    """
    sbb_trunc = []
    for item in sbb:
        if item[0] == stop_before_header:
            break
        else:
            sbb_trunc.append(item)
    sbb_trunc_str = json.dumps(sbb_trunc, sort_keys=True, indent=json_indent)
    hash_tweak = 2
    return sv.secure_hash(sbb_trunc_str, hash_tweak)

def check_opened_output_commitments(sbb_dict, db):
    """ Check that opened output commitments open correctly.
    TODO: ensure that all such necessary checks are done, not just for ones
          that are posted.
    """
    coms = \
        sbb_dict['proof:outcome_check']\
                ['opened_output_commitments']
    assert isdict(coms, db['race_ids'])
    for race_id in db['race_ids']:
        assert isdict(coms[race_id], db['opl'])
        for k in db['opl']:
            assert isdict(coms[race_id][k], db['p_list'])
            for p in db['p_list']:
                assert isdict(coms[race_id][k][p], db['row_list'])
                for i in db['row_list']:
                    assert isdict(coms[race_id][k][p][i],
                                  ['ru', 'rv', 'u', 'v', 'y'])
                    ru = coms[race_id][k][p][i]['ru']
                    assert isinstance(ru, str)
                    rv = coms[race_id][k][p][i]['rv']
                    assert isinstance(rv, str)
                    u = coms[race_id][k][p][i]['u']
                    assert isinstance(u, int) and \
                        0 <= u < db['races'][race_id]['race_modulus']
                    v = coms[race_id][k][p][i]['v']
                    assert isinstance(v, int) and \
                        0 <= v < db['races'][race_id]['race_modulus']
                    y = coms[race_id][k][p][i]['y']
                    assert isinstance(y, int) and \
                        0 <= y < db['races'][race_id]['race_modulus']
                    assert y == (u+v) % db['races'][race_id]['race_modulus']
                    cu = sbb_dict['proof:all_output_commitments']\
                         ['commitments'][race_id][k][p][i]['cu']
                    cv = sbb_dict['proof:all_output_commitments']\
                         ['commitments'][race_id][k][p][i]['cv']
                    assert cu == sv.com(u, ru)
                    assert cv == sv.com(v, rv)
    print('check_opened_output_commitments: passed.')

def check_opened_output_commitment_tallies(sbb_dict, db):
    """ Check that for each k, the opened output commitments lagranage
        and tally to values given in tally.
    """
    opened_coms = \
        sbb_dict['proof:outcome_check']\
                ['opened_output_commitments']
    for k in db['opl']:
        # verify tally for this pass/copy k
        tally_k = dict()
        for race_id in db['race_ids']:
            tally_k[race_id] = dict()  # choices to counts
            for choice in sbb_dict['setup:races']\
                ['ballot_style_race_dict'][race_id]['choices']:
                if choice[0] != '*':
                    tally_k[race_id][choice] = 0
            for p in db['p_list']:
                share_list = []
                for i_int, i in enumerate(db['row_list']):
                    y = opened_coms[race_id][k][p][i]['y']
                    share_list.append((i_int+1, y))
                w = sv.lagrange(share_list,
                                db['rows'],
                                db['threshold'],
                                db['races'][race_id]['race_modulus'])
                # convert w back to string version of choice
                # see sv_race.choice_int2str
                choice_bytes = sv.int2bytes(w)
                choice_str = choice_bytes.decode()
                # assert self.is_valid_choice(choice_str)
                # print(race_id, k, iy, choice_str)
                cnt = tally_k[race_id].get(choice_str, 0)
                tally_k[race_id][choice_str] = cnt + 1
        assert tally_k == db['tally']
    print('check_opened_output_commitment_tallies: passed.')

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
    pd = sbb_dict['proof:input_check:pik_for_k_in_icl']['pik_dict']
    assert isdict(pd, db['race_ids'])
    for race_id in db['race_ids']:
        assert isdict(pd[race_id], db['icl'])
        for k in db['icl']:
            assert isdict(pd[race_id][k], db['p_list'])
            p_list = set(db['p_list'])
            for p in db['p_list']:
                assert pd[race_id][k][p] in p_list
                p_list.remove(pd[race_id][k][p])
    print('check_inputs_pik: passed.')

def check_inputs_outputs_openings(sbb_dict, db):
    """ Check input openings for testing consistency with output openings. """

    coms = sbb_dict['proof:input_check:input_openings']['opened_commitments']
    for race_id in db['race_ids']:
        for k in db['icl']:
            # check correspondence
            pass

def check_inputs_output_openings(sbb_dict, db):
    """ Check output openings used for consistency with input openings. """

def check_inputs_t_value(sbb_dict, db):
    """ Check that t-values are correct for halfs that are opened. """
    for race_id in db['races']:
        # leftright maps p-list elements to 'left' or 'right'
        leftright = sbb_dict['proof:verifier_challenges']\
                    ['challenges']['leftright'][race_id] # same for all i

        # pik_dict maps k to mapping from p_list elements to p_list elts.
        # this is py back to px
        pik_dict = sbb_dict['proof:pik_for_k_in_icl']['pik_dict']
        for k in db['icl']:
            pik = pik_dict[k]
            # icom maps i, p, to
            #  {ballot_id,"com(u,ru)","i","race_id","ru","u"} or
            #  {ballot_id,"com(v,rv)","i","race_id","rv","v"} or
            icom = sbb_dict['proof:input_check:input_openings']\
                   ['opened_commitments'][race_id]

            # t_value_dict maps p and i to {"tu":value, "tv":value}
            t_value_dict = sbb_dict['t_values'][race_id][k]
            for py in db['p_list']:
                px = pik[py]
                lr = leftright[px]        # and not py
                assert lr == 'left' or lr == 'right'
                # find input commitment
                icom = db['cast_votes'][ix]


if __name__ == "__main__":
    filename = sys.argv[1]
    print("Verifying election with SBB contents in:", filename)
    verify(filename)
