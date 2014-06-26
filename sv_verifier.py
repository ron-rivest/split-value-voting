# sv_verifier.py
# python3
# Code for verifier portion of an election
# This should work for simulated election, or a real election.

""" Usage: python3 sv_verifier.py election_id.sbb.txt

           where election_id.sbb.txt is the file having
           the contents of the secure bulletin board (json format).
"""

# MIT open-source license. (See https://github.com/ron-rivest/split-value-voting.git)

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
               'proof:output_commitments',
               'proof:output_commitment_t_values',
               'proof:verifier_challenges',
               'proof:outcome_check',
               'proof:input_consistency:input_openings',
               'proof:input_consistency:output_openings',
               'proof:input_consistency:pik_for_k_in_icl',
               'election:done.',
               'sbb:close']

# attributes expected for each header
ATTRIBUTES = {'sbb:open': ['election_id', 'time'],
              'setup:start': ['election_id', 'time',
                              'about', 'legend'],
              'setup:races': ['ballot_style_race_dict'],
              'setup:voters': ['n_voters', 'ballot_id_len'],
              'setup:server-array':
                  ['cols', 'rows', 'n_reps', 'threshold', 'json_indent'],
              'setup:finished': ['time'],
              'casting:votes': ['cast_vote_dict'],
              'tally:results': ['election_id', 'tally', 'time'],
              'proof:output_commitments': ['commitments'],
              'proof:output_commitment_t_values': ['t_values'],
              'proof:verifier_challenges': ['challenges', 'sbb_hash'],
              'proof:outcome_check':
                  ['opened_output_commitments'],
              'proof:input_consistency:input_openings': ['opened_commitments'],
              'proof:input_consistency:output_openings': ['opened_commitments'],
              'proof:input_consistency:pik_for_k_in_icl': ['pik_dict'],
              'election:done.': ['time', 'election_id'],
              'sbb:close': ['time']
             }

# 'cheat sheet' on sbb formats:
# casting:votes['cast_vote_dict'][race_id][p][i]['ballot_id']
# casting:votes['cast_vote_dict'][race_id][p][i]['cu']
# casting:votes['cast_vote_dict'][race_id][p][i]['cv']
# tally:results['election_id']
# tally:results['tally'][race_id]{choice: cnt}
# proof:output_commitments['commitments'][race_id][k][p][i]['cu']
# proof:output_commitments['commitments'][race_id][k][p][i]['cv']
# proof:output_commitment_t_values['t-values'][race_id][p][i]['tu']
# proof:output_commitment_t_values['t-values'][race_id][p][i]['tv']
# proof:verifier_challenges['challenges']['cut']['icl'][...]
# proof:verifier_challenges['challenges']['cut']['opl'][...]
# proof:verifier_challenges['leftright'][race_id]{ px: left or right }
# proof:verifier_challenges['sbb_hash']
# proof:outcome_check['opened_output_commitments][race_id][k][p][i]['ru']
# proof:outcome_check['opened_output_commitments][race_id][k][p][i]['rv']
# proof:outcome_check['opened_output_commitments][race_id][k][p][i]['u']
# proof:outcome_check['opened_output_commitments][race_id][k][p][i]['v']
# proof:outcome_check['opened_output_commitments][race_id][k][p][i]['y']
# in following lines let PIC stand for "proof:input_consistency"
# PIC:input_openings['opened_commitments'][race_id][p][i]['ru']
# PIC:input_openings['opened_commitments'][race_id][p][i]['u'] or
# PIC:input_openings['opened_commitments'][race_id][p][i]['rv']
# PIC:input_openings['opened_commitments'][race_id][p][i]['v']
# PIC:output_openings['opened_commitments'][race_id][k][p][i]['ru']
# PIC:output_openings['opened_commitments'][race_id][k][p][i]['u'] or
# PIC:output_openings['opened_commitments'][race_id][k][p][i]['rv']
# PIC:output_openings['opened_commitments'][race_id][k][p][i]['v'] or
# PIC:pik_for_k_in_icl['pik_dict'][race_id][k]{px: py}

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

    sbb = sv.load(sbb_filename)

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
    check_opened_output_commitments(sbb_dict, db)
    check_opened_output_commitment_tallies(sbb_dict, db)
    check_input_consistency(sbb_dict, db)
    print('all verifications passed!!')

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
        if 'time' in item_dict:
            item_time = item_dict['time']
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
    assert json_indent is None or isinstance(json_indent, int)
    assert json_indent is None or json_indent >= 0
    db['json_indent'] = json_indent
    sv.set_json_indent(json_indent)
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
    """ Read output commitments from proof:output_commitments
    and put results into db.
    """
    coms = sbb_dict['proof:output_commitments']['commitments']
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
    """ Read t values from proof:output_commitment_t_values, and
        save them in db.
    """
    ts = sbb_dict['proof:output_commitment_t_values']['t_values']
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
    sbb_hash2 = sv.bytes2hex(hash_sbb(sbb, stop_before_header))
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

def hash_sbb(sbb, stop_before_header):
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
    sbb_trunc_str = sv.dumps(sbb_trunc)
    hash_tweak = 2
    return sv.secure_hash(sbb_trunc_str, hash_tweak)

def check_opened_output_commitments(sbb_dict, db):
    """ Check that opened output commitments open correctly.
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
                    cu = sbb_dict['proof:output_commitments']\
                         ['commitments'][race_id][k][p][i]['cu']
                    cv = sbb_dict['proof:output_commitments']\
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

def check_input_consistency(sbb_dict, db):
    """ Do all input checks.
        Check that t-values are consistent with opened inputs and
        opened outputs, for k in icl.  Also check that lagrange
        of t-value pairs for a given voter yields (t,-t).
    """
    check_input_consistency_pik(sbb_dict, db)
    check_input_consistency_t_values(sbb_dict, db)
    check_input_consistency_input_openings(sbb_dict, db)
    check_input_consistency_output_openings(sbb_dict, db)

def check_input_consistency_pik(sbb_dict, db):
    """ Check that piks look OK. """
    pd = sbb_dict['proof:input_consistency:pik_for_k_in_icl']['pik_dict']
    assert isdict(pd, db['race_ids'])
    for race_id in db['race_ids']:
        assert isdict(pd[race_id], db['icl'])
        for k in db['icl']:
            assert isdict(pd[race_id][k], db['p_list'])
            p_list = set(db['p_list'])
            for p in db['p_list']:
                assert pd[race_id][k][p] in p_list
                p_list.remove(pd[race_id][k][p])
    print('check_input_consistency_pik: passed.')

def check_input_consistency_input_openings(sbb_dict, db):
    """ Check that input openings are correct,
        for those halves that are opened.
    """
    oc = sbb_dict['proof:input_consistency:input_openings']\
                 ['opened_commitments']
    cv = sbb_dict['casting:votes']['cast_vote_dict']
    for race_id in db['races']:
        ocr = oc[race_id]
        cvr = cv[race_id]
        for p in db['p_list']:
            ocrp = ocr[p]
            cvrp = cvr[p]
            for i in db['row_list']:
                ocrpi = ocrp[i]
                cvrpi = cvrp[i]
                if 'u' in ocrpi:
                    assert cvrpi['cu'] == sv.com(ocrpi['u'],
                                                 ocrpi['ru'])
                else:
                    assert cvrpi['cv'] == sv.com(ocrpi['v'],
                                                 ocrpi['rv'])
    print('check_input_consistency_input_openings: passed.')

def check_input_consistency_output_openings(sbb_dict, db):
    """ Check that output openings are correct,
        for those halves that are opened.
    """
    oooc = sbb_dict['proof:input_consistency:output_openings']\
                   ['opened_commitments']
    occ = sbb_dict['proof:output_commitments']['commitments']
    for race_id in db['races']:
        ooocr = oooc[race_id]
        occr = occ[race_id]
        for k in db['icl']:
            ooocrk = ooocr[k]
            occrk = occr[k]
            for p in db['p_list']:
                ooocrkp = ooocrk[p]
                occrkp = occrk[p]
                for i in db['row_list']:
                    ooocrkpi = ooocrkp[i]
                    occrkpi = occrkp[i]
                    if 'u' in ooocrkpi:
                        assert occrkpi['cu'] == sv.com(ooocrkpi['u'],
                                                       ooocrkpi['ru'])
                    else:
                        assert occrkpi['cv'] == sv.com(ooocrkpi['v'],
                                                       ooocrkpi['rv'])
    print('check_input_consistency_output_openings: passed.')

def check_input_consistency_t_values(sbb_dict, db):
    """ Check that t-values are correct for halfs that are opened. """
    for race_id in db['races']:
        # leftright maps p-list elements to 'left' or 'right'
        leftright = sbb_dict['proof:verifier_challenges']\
                    ['challenges']['leftright'][race_id] # same for all i
        race_modulus = sbb_dict['setup:races']['ballot_style_race_dict']\
                       [race_id]['race_modulus']
        # pik_dict maps race_id, k to
        #   mapping from p_list elements to p_list elts.
        # (mapping py back to px)
        pik_dict = sbb_dict['proof:input_consistency:pik_for_k_in_icl']\
                           ['pik_dict']
        for k in db['icl']:
            pik = pik_dict[race_id][k]  # {py: px}
            icom = sbb_dict['proof:input_consistency:input_openings']\
                   ['opened_commitments'][race_id]
            ocom = sbb_dict['proof:input_consistency:output_openings']\
                   ['opened_commitments'][race_id][k]
            #  icom maps p, i to {"ru":.., "u":..} or {"rv":.., "v":..}
            #  ocom maps p, i to {"ru":.., "u":..} or {"rv":.., "v":..}
            for py in db['p_list']:
                px = pik[py]
                tu_list = []
                tv_list = []
                for i in db['row_list']:
                    icompi = icom[px][i]
                    ocompi = ocom[py][i]
                    assert set(icompi.keys()) == set(ocompi.keys())
                    # t_value_dict gives {"tu":value, "tv":value}
                    t_value_dict = sbb_dict['proof:output_commitment_t_values']\
                            ['t_values'][race_id][k][px][i]
                    lr = leftright[px]        # and not py
                    assert lr == 'left' or lr == 'right'
                    if lr == 'left':
                        iuv = icompi['u']
                        ouv = ocompi['u']
                        tuv = t_value_dict['tu']
                    else:
                        iuv = icompi['v']
                        ouv = ocompi['v']
                        tuv = t_value_dict['tv']
                    assert tuv == (ouv-iuv) % race_modulus
                    tu_list.append(t_value_dict['tu'])
                    tv_list.append(t_value_dict['tv'])
                # check that tu_list and tv_list lagrange to (t, -t)
                tu_list = list(enumerate(tu_list, 1))
                tu0 = sv.lagrange(tu_list, db['rows'], db['threshold'],
                                  race_modulus)
                tv_list = list(enumerate(tv_list, 1))
                tv0 = sv.lagrange(tv_list, db['rows'], db['threshold'],
                                  race_modulus)
                assert ((tu0 + tv0) % race_modulus) == 0
    print('check_input_consistency_t_values: passed.')


if __name__ == "__main__":
    filename = sys.argv[1]
    print("Verifying election with SBB contents in:", filename)
    verify(filename)
