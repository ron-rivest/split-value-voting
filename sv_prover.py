# sv_prover.py
# python3
# Code for prover portion of simulated election

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

def make_proof(election):
    """ Prove that the outcome is correct. (Make it verifiable.) """

    # write out commitments for outputs of last column
    make_full_output(election)
    post_output_commitments(election)
    compute_and_post_t_values(election)

    # make verifier challenges to proof
    challenges = make_verifier_challenges(election)

    # part 1 of proof production
    prove_outcome_correct(election, challenges)

    return
    # part 2 of proof production
    # make proof of consistency of icl copies with input
    prove_input_consistent(election, challenges)
    compute_and_post_pik_list(election, challenges)
 
##############################################################################
# output section
##############################################################################

def make_full_output(election):
    """ Make commitments to output values and save them.

    For each race,
    for each of n_reps copies (indexed by k),
    for each row (indexed by i)
    for each of the n vote shares (call them y)
    output two commitments.
    """
    rows = election.server.rows
    cols = election.server.cols
    full_output = dict()
    for race in election.races:
        race_modulus = race.race_modulus
        race_id = race.race_id
        full_output[race_id] = dict()
        for k in election.k_list:
            full_output[race_id][k] = dict()
            for py in election.p_list:
                full_output[race_id][k][py] = dict()
                for i in election.server.row_list:
                    rand_name = \
                        election.server.sdb[race_id][i][cols-1]['rand_name']
                    sdbp = election.server.sdb[race_id][i][cols-1][k]
                    y = sdbp['y'][py]
                    (u, v) = sv.get_sv_pair(y, rand_name, race_modulus)
                    ru = sv.bytes2base64(sv.get_random_from_source(rand_name))
                    rv = sv.bytes2base64(sv.get_random_from_source(rand_name))
                    pair = (sv.com(u, ru), sv.com(v, rv))
                    sdbp['u'][py] = u
                    sdbp['v'][py] = v
                    sdbp['ru'][py] = ru
                    sdbp['rv'][py] = rv
                    sdbp['pair'][py] = pair
                    ballot = {'y': y, 'u': u, 'v': v, 'ru': ru, 'rv': rv, 'pair': pair}
                    full_output[race_id][k][py][i] = ballot
    election.full_output = full_output

def post_output_commitments(election):
    """ Post output votes onto SBB. """
    full_output = election.full_output
    coms = dict()
    # same as full_output, but only giving non-secret values (i.e. pairs)
    for race in election.races:
        race_modulus = race.race_modulus
        race_id = race.race_id
        coms[race_id] = dict()
        for k in election.k_list:
            coms[race_id][k] = dict()
            for py in election.p_list:
                coms[race_id][k][py] = dict()
                for i in election.server.row_list:
                    coms[race_id][k][py][i] = \
                        { 'pair': full_output[race_id][k][py][i]['pair'] }
    election.output_commitments = coms    
    election.sbb.post("proof:all_output_commitments",
                      {"commitments": coms},
                      time_stamp=False)

def compute_and_post_t_values(election):
    """ Compute a t value for each race and ballot in that race, post it.

    In a real implementation, this code requires inter-processor communication.

    Note on the math: Here we take an arbitrary input commitment to u
    (called ux, since it is part of an x value), and trace it through the
    mix till it is output at the other end as a commitment to u (called
    uy, since it is part of output value y).  The difference uy-ux we
    call tu.  Similarly for tv.  The pairs (tu,tv) for a given vote
    should lagrange-together to form a pair of the form (t,-t).  The
    verifier should check this.

    This provides such t_values for *all* k, even though we will only
    need them for k in icl.  But the t values need to be committed to
    before the left/right challenges are made, and it seems easier
    (although a bit more expensive storage-wise) to have the tvalues
    be part of a single commit phase.
    """
    server = election.server
    cols = server.cols
    t_values = dict()
    for race in election.races:
        race_id = race.race_id
        t_values[race_id] = dict()
        for k in election.k_list:
            t_values[race_id][k] = dict()
            for i in election.server.row_list:
                t_values[race_id][k][i] = dict()
                for px in election.p_list:
                    t_values[race_id][k][i][px] = dict()
                    ux = server.sdb[race_id][i][0]['u'][px]
                    vx = server.sdb[race_id][i][0]['v'][px]
                    py = px
                    for j in range(cols):
                        pi_inv = server.sdb[race_id][i][j][k]['pi_inv']
                        py = pi_inv[py]
                    uy = server.sdb[race_id][i][cols-1][k]['u'][py]
                    vy = server.sdb[race_id][i][cols-1][k]['v'][py]
                    tu = (uy-ux) % race.race_modulus
                    tv = (vy-vx) % race.race_modulus
                    t_values[race_id][k][i][px]["tu"] = tu
                    t_values[race_id][k][i][px]["tv"] = tv
    election.sbb.post("proof:t_values_for_all_output_commitments",
                      {"t_values": t_values},
                      time_stamp=False)

##############################################################################
# challenge section
##############################################################################

def make_verifier_challenges(election):
    """ Return a dict containing "verifier challenges" for this proof.

        This is based on randomness (hash of sbb, fiat-shamir style),
        but could also incorporate additional random input (e.g.
        dice rolls).
    """
    sbb_hash = election.sbb.hash_sbb(public=True)
    election.sbb_hash = sbb_hash
    rand_name = "verifier_challenges"
    sv.init_randomness_source(rand_name, sbb_hash)
    challenges = dict()
    make_cut_and_choose_challenges(election, rand_name, challenges)
    make_left_right_challenges(election, rand_name, challenges)
    election.sbb.post("proof:verifier_challenges",
                      {"sbb_hash": sv.bytes2hex(sbb_hash),
                       "challenges": challenges},
                      time_stamp=False)
    return challenges

def make_cut_and_choose_challenges(election, rand_name, challenges):
    """ Return random split of [0,1,...,n_reps-1] into two lists.

    Use specified randomness source.
    This icl/opl split will be the same for all races.
    (This can be easily changed if desired.)
    # icl = subset of election.k_list used for "input comparison"
    # opl = subset of election.k_list used for "output production"
    Save results in challenges dict.
    """
    m = election.n_reps // 2
    pi = sv.random_permutation(2*m, rand_name)
    pi = [pi[i] for i in range(2*m)]
    # icl = copies for input comparison
    # opl = copies for output production
    icl = [election.k_list[i] for i in sorted(pi[:m])]
    opl = [election.k_list[i] for i in sorted(pi[m:])]
    challenges['cut'] = {'icl': icl, 'opl': opl}

def make_left_right_challenges(election, rand_name, challenges):
    """ make dict with a list of n_voters left/right challenges for each race.

        Modify dict challenges to have a per race list of True/False values
        of length n_voters (True = left).
    """
    leftright_dict = dict()
    # sorting needed in next line else result depends on enumeration order
    # (sorting is also done is sv_verifier.py)
    for race_id in sorted(election.race_ids):
        leftright = ["left"\
                     if bool(sv.get_random_from_source(rand_name, modulus=2))\
                     else "right"\
                     for i in range(election.n_voters)]
        leftright_dict[race_id] = leftright
    challenges['leftright'] = leftright_dict

##############################################################################
# proving outcome correct section
##############################################################################

def prove_outcome_correct(election, challenges):
    """ Produce proof sufficient to prove election outcome correct (i.e.,
    consistent with output commitments.

    Here challenges['opl'] is a size-m subset of range(2*m) that indicates
    which lists are to be opened for comparison purposes.  (We don't combine
    shares here; that is done elsewhere.  Also, verification that commitments
    open properly is done by verifier.)
    This routine just releases all information needed for output comparisons
    and proof verification.
    """
    opl = challenges['cut']['opl']
    opened = dict()
    cols = election.server.cols
    for race in election.races:
        race_id = race.race_id
        opened[race_id] = dict()
        for k in opl:
            opened[race_id][k] = dict()
            for py in election.p_list:
                opened[race_id][k][py] = dict()
                for i in election.server.row_list:
                    y = election.server.sdb[race_id][i][cols-1][k]['y'][py]
                    u = election.server.sdb[race_id][i][cols-1][k]['u'][py]
                    v = election.server.sdb[race_id][i][cols-1][k]['v'][py]
                    ru = election.server.sdb[race_id][i][cols-1][k]['ru'][py]
                    rv = election.server.sdb[race_id][i][cols-1][k]['rv'][py]
                    pair = election.server.sdb[race_id][i][cols-1][k]['pair'][py]
                    opened[race_id][k][py][i] = \
                        {"y": y,
                         "u": u,
                         "v": v,
                         "ru": ru,
                         "rv": rv,
                         "pair": pair}
    election.sbb.post("proof:outcome_check:opened_output_commitments",
                      {"opened_commitments": opened},
                      time_stamp=False)

##############################################################################
# proving input consistent  section
##############################################################################

def prove_input_consistent(election, challenges):
    """ Produce proof sufficient to prove cast votes consistent
        with output lists with indices in challenges['icl'].
    """
    icl = challenges['cut']['icl']
    leftright_dict = challenges['leftright']

    commitments = dict()
    for race in election.races:
        race_id = race.race_id
        leftright = leftright_dict[race_id]
        commitments_in_race = []
        for i in election.server.row_list:
            input_pair_list = \
                make_list_of_input_commitment_pairs(election, race, i)
            commitments_in_race.append(\
                half_open_commitments_from_list(election,
                                                input_pair_list,
                                                leftright))
        commitments[race_id] = commitments_in_race  # list of length rows
    election.sbb.post("proof:input_check:input_openings",
                      {"opened_commitments": commitments},
                      time_stamp=False)

    # half-open corresponding outputs
    commitments_to_post = []
    for race in election.races:
        race_id = race.race_id
        leftright = leftright_dict[race_id]
        for k in icl:
            for i in election.server.row_list:
                output_pair_list = \
                    make_list_of_output_commitment_pairs(election, race, i, k)
                commitments_to_post.append(\
                    half_open_commitments_from_list(\
                        election, output_pair_list, leftright))
    election.sbb.post("proof:input_check:output_openings",
                      {"opened_commitments": commitments_to_post},
                      time_stamp=False)

def half_open_commitments_from_list(election, commitments, leftright):
    """ Open 1/2 of the commitments in the given list of pairs
        of commitments.
        leftright is a list of "left"/"right" of the same length.
        This is used for both input and output commitments
    """
    assert len(commitments) == len(leftright)
    commitments_to_post = []
    for com, pick in zip(commitments, leftright):
        com_to_post = com[0] if pick == "left" else com[1]
        commitments_to_post.append(com_to_post)
    return commitments_to_post

def make_list_of_input_commitment_pairs(election, race, row_i):
    """ Make list of input commitment pairs (cast votes) for race and row_i """
    # note that election.cast_votes is in "canonical" order
    # (sorted into increasing order by ballot id).
    list_of_input_commitment_pairs = []
    for (race_id, ballot_id, i, x, u, v, ru, rv, pair) in \
        election.cast_votes:
        if race_id == race.race_id and i == row_i:
            ucom = {"race_id": race_id,
                    "ballot_id": ballot_id,
                    "i": i,
                    "u": u,
                    "ru": ru,
                    "com(u,ru)": pair[0]}
            vcom = {"race_id": race_id,
                    "ballot_id": ballot_id,
                    "i": i,
                    "v": v,
                    "rv": rv,
                    "com(v,rv)": pair[1]}
            list_of_input_commitment_pairs.append((ucom, vcom))
    return list_of_input_commitment_pairs

def make_list_of_output_commitment_pairs(election, race, i, k):
    """ Make list of output commitment pairs for given race,
        row i, and given copy index (k).
    """
    assert k in election.k_list
    # first make list in unpermuted order
    cols = election.server.cols
    race_id = race.race_id
    list_of_output_commitment_pairs = []
    sdbp = election.server.sdb
    for iy in range(election.n_voters):
        ucom = {"race_id": race_id,
                "py": py,
                "i": i,
                "u": sdbp[race_id][i][cols-1][k]['u'][py],
                "ru": sdbp[race_id][i][cols-1][k]['ru'][py],
                "com(u,ru)": sdbp[race_id][i][cols-1][k]['pair'][py][0]}
        vcom = {"race_id": race_id,
                "py": py,
                "i": i,
                "v": sdbp[race_id][i][cols-1][k]['v'][py],
                "rv": sdbp[race_id][i][cols-1][k]['rv'][py],
                "com(v,rv)": sdbp[race_id][i][cols-1][k]['pair'][py][1]}
        list_of_output_commitment_pairs.append((ucom, vcom))
    # next is to permute it back into same order as input lists
    for j in range(cols-1, -1, -1):
        pi_inv = sdbp[race_id][i][j][k]['pi_inv']
        list_of_output_commitment_pairs = \
            sv.apply_permutation(pi_inv, list_of_output_commitment_pairs)
    return list_of_output_commitment_pairs

def compute_and_post_pik_list(election, challenges):
    """ Compute a permutation pi for each race and ballot in that race, post it.

    In a real implementation, this code requires inter-processor communication.

    This is similar to the t_value computation, except (for security!) only
    for those k in icl.  Also note that there is no dependence on the row (i),
    so we don't need to loop on i.
    """
    icl = challenges['cut']['icl']
    server = election.server
    cols = server.cols
    pik_list = []
    for race in election.races:
        race_id = race.race_id
        for k in icl:
            pik = dict()
            for py in range(election.p_list):
                px = py
                px_int = int(px[1:])
                for j in range(cols):
                    pi = server.sdb[race_id]['a'][j][k]['pi']
                    px_int = pi[px_int]
                px = "p"+str(px_int)
                pik[py] = px
            # now pik maps py's to their original px's
            pik_list.append({"race_id": race_id,
                             "k": k,
                             "pik": pik})
    election.sbb.post("proof:input_check:pik_for_k_in_icl",
                      {"list": pik_list},
                      time_stamp=False)


