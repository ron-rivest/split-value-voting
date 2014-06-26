# sv_prover.py
# python3
# Code for prover portion of simulated election

# MIT open-source license. (See https://github.com/ron-rivest/split-value-voting.git)

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

    # part 2 of proof production
    # make proof of consistency of icl copies with input
    prove_input_consistent(election, challenges)
    compute_and_post_pik_dict(election, challenges)

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
                    cu = sv.com(u, ru)
                    cv = sv.com(v, rv)
                    sdbp['u'][py] = u
                    sdbp['v'][py] = v
                    sdbp['ru'][py] = ru
                    sdbp['rv'][py] = rv
                    sdbp['cu'][py] = cu
                    sdbp['cv'][py] = cv
                    ballot = {'y': y, 'u': u, 'v': v,
                              'ru': ru, 'rv': rv, 'cu': cu, 'cv': cv}
                    full_output[race_id][k][py][i] = ballot
    election.full_output = full_output

def post_output_commitments(election):
    """ Post output votes onto SBB. """
    full_output = election.full_output
    coms = dict()
    # same as full_output, but only giving non-secret values (i.e. cu, cv)
    for race in election.races:
        race_id = race.race_id
        coms[race_id] = dict()
        for k in election.k_list:
            coms[race_id][k] = dict()
            for py in election.p_list:
                coms[race_id][k][py] = dict()
                for i in election.server.row_list:
                    coms[race_id][k][py][i] = \
                        {'cu': full_output[race_id][k][py][i]['cu'],
                         'cv': full_output[race_id][k][py][i]['cv']}
    election.output_commitments = coms
    election.sbb.post("proof:output_commitments",
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
    ts = dict()
    for race in election.races:
        race_id = race.race_id
        ts[race_id] = dict()
        for k in election.k_list:
            ts[race_id][k] = dict()
            for px in election.p_list:
                ts[race_id][k][px] = dict()
                for i in election.server.row_list:
                    ts[race_id][k][px][i] = dict()
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
                    ts[race_id][k][px][i]["tu"] = tu
                    ts[race_id][k][px][i]["tv"] = tv
    election.sbb.post("proof:output_commitment_t_values",
                      {"t_values": ts},
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
        leftright = dict()
        for p in election.p_list:   # note: p_list is already sorted
            leftright[p] = "left"\
                           if bool(sv.get_random_from_source(rand_name,
                                                             modulus=2))\
                           else "right"
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
                    # cu, cv already given in output commitments
                    # so we only need to supply opening values here
                    # cu = election.server.sdb[race_id][i][cols-1][k]['cu'][py]
                    # cv = election.server.sdb[race_id][i][cols-1][k]['cv'][py]
                    opened[race_id][k][py][i] = \
                        {"y": y,
                         "u": u,
                         "v": v,
                         "ru": ru,
                         "rv": rv
                        }
    election.sbb.post("proof:outcome_check",
                      {"opened_output_commitments": opened},
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

    coms = dict()
    for race in election.races:
        race_id = race.race_id
        leftright = leftright_dict[race_id]
        coms[race_id] = dict()
        for px in election.p_list:
            coms[race_id][px] = dict()
            for i in election.server.row_list:
                vote = election.cast_votes[race_id][px][i]
                if leftright[px] == "left":
                    com = {"u": vote['u'], "ru": vote['ru']}
                else:
                    com = {"v": vote['v'], "rv": vote['rv']}
                coms[race_id][px][i] = com
    election.sbb.post("proof:input_consistency:input_openings",
                      {"opened_commitments": coms},
                      time_stamp=False)

    # half-open corresponding outputs
    coms = dict()
    for race in election.races:
        race_id = race.race_id
        leftright = leftright_dict[race_id] # maps p to left/right
        coms[race_id] = dict()
        for k in icl:
            coms[race_id][k] = dict()
            for py in election.p_list:
                coms[race_id][k][py] = dict()
            for py in election.p_list:
                for i in election.server.row_list:
                    cols = election.server.cols
                    sdbp = election.server.sdb
                    px = py
                    for j in range(cols-1, -1, -1):
                        pi = sdbp[race_id][i][j][k]['pi']
                        px = pi[px]
                    if leftright[px] == "left":
                        com = {"u": sdbp[race_id][i][cols-1][k]['u'][py],
                               "ru": sdbp[race_id][i][cols-1][k]['ru'][py]}
                    else:
                        com = {"v": sdbp[race_id][i][cols-1][k]['v'][py],
                               "rv": sdbp[race_id][i][cols-1][k]['rv'][py]}
                    coms[race_id][k][py][i] = com
    election.sbb.post("proof:input_consistency:output_openings",
                      {"opened_commitments": coms},
                      time_stamp=False)

def compute_and_post_pik_dict(election, challenges):
    """ Compute a permutation pi for each race and ballot in that race, post it.

    In a real implementation, this code requires inter-processor communication.

    This is similar to the t_value computation, except (for security!) only
    for those k in icl.  Also note that there is no dependence on the row (i),
    so we don't need to loop on i.
    """
    icl = challenges['cut']['icl']
    server = election.server
    cols = server.cols
    pik_dict = dict()
    for race in election.races:
        race_id = race.race_id
        pik_dict[race_id] = dict()
        for k in icl:
            pik_dict[race_id][k] = dict()
            for py in election.p_list:
                px = py
                for j in range(cols-1, -1, -1):
                    pi = server.sdb[race_id]['a'][j][k]['pi']
                    px = pi[px]
                pik_dict[race_id][k][py] = px
            # now pik maps py's to their original px's
    election.sbb.post("proof:input_consistency:pik_for_k_in_icl",
                      {'pik_dict': pik_dict},
                      time_stamp=False)


