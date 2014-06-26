# sv_tally.py
# python3
# Code for tally portion of simulated election

# MIT open-source license. (See https://github.com/ron-rivest/split-value-voting.git)

import sys

import sv


def compute_tally(election):
    """ Compute tallies for this election.

    Data is from last column of mix servers.
    """
    server = election.server
    cols = server.cols
    election.tally = dict()
    for race in election.races:
        race_id = race.race_id
        for k in election.k_list:
            choice_int_list = []
            for p in election.p_list:
                share_list = \
                    [(row+1, server.sdb[race_id][i][cols-1][k]['y'][p]) \
                     for row, i in enumerate(election.server.row_list)]
                choice_int = sv.lagrange(share_list, server.rows,\
                                         server.threshold, race.race_modulus)
                choice_int_list.append(choice_int)
            choice_str_list = [race.choice_int2str(choice_int)
                               for choice_int in choice_int_list]
            choice_str_list = sorted(choice_str_list)
            if k == election.k_list[0]:
                last_choice_str_list = choice_str_list
            else:
                assert choice_str_list == last_choice_str_list
        # now compute tally for this race
        tally = dict()
        for choice_str in race.choices:
            if not all([c == '*' for c in choice_str]):
                tally[choice_str] = 0
        for choice_str in choice_str_list:
            tally[choice_str] = tally.get(choice_str, 0) + 1
        # save it
        race.tally = tally
        election.tally[race_id] = tally

def print_tally(election, f_out=sys.stdout):
    """ Print tallies computed for this election to file f_out.

    Uses results compiled by compute_tally, and saved in race.tally fields.
    """
    print()
    print("election results:", file=f_out)
    for race in election.races:
        print("    race: ", race.race_id, file=f_out)
        tally_list = [(count, choice_str) \
                      for choice_str, count in list(race.tally.items())]
        tally_list = sorted(tally_list)
        tally_list.reverse()                  # put winners first!
        for count, choice_str in tally_list:
            print("    ", "%7d"%count, " ", choice_str, file=f_out)
    print("end of election results.", file=f_out)
    print()

def post_tally(election):
    """ Save tallies to sbb. """
    election.sbb.post("tally:results",
                      {"election_id": election.election_id,
                       "tally": election.tally})
