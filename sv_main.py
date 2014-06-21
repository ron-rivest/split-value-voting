# sv_main.py
# python3
# Ronald L. Rivest and Michael O. Rabin

"""
Top-level routine for running simulated election using split-value method.

Usage: python3 sv_main.py
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

import cProfile
import sys
assert sys.version_info[0] == 3

import sv_election
import sv_verifier

def do_election():
    """ Do (simulate) an election. """

    election_parameters = {\
        "election_id": "test01",
        "ballot_style":\
            [("taxes", ("yes", 
                        "no")),\
             ("mayor", ("tom", 
                        "rufus", 
                        "****************"))],  # 16-char write-ins allowed
        "n_voters": 11,    # voters
        "n_reps": 4,      # (# of replicas aka 2m)
        "n_fail": 1,      # how many servers may fail
        "n_leak": 1}      # how many servers may leak

    print("starting election (simulation).")
    print("election parameters:")
    print("    election id =", election_parameters["election_id"])
    print("    ballot style =", election_parameters["ballot_style"])
    print("    n_voters =", election_parameters["n_voters"])
    print("    n_reps =", election_parameters["n_reps"])
    print("    n_fail =", election_parameters["n_fail"])
    print("    n_leak =", election_parameters["n_leak"])

    election = sv_election.Election(election_parameters)

    election.run_election()

    sbb_filename = election_parameters["election_id"] + ".sbb.txt"
    election.sbb.print_sbb(public=True, sbb_filename=sbb_filename)

    print("election finished.")

    print()
    print("beginning verification...")
    sv_verifier.verify(sbb_filename)
    print("done.")

if __name__ == "__main__":
    # cProfile.run("do_election()")
    do_election()
