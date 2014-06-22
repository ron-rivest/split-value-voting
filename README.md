Python3 code for Rabin/Rivest end-to-end split-value voting method(s).

The relevant paper: http://people.csail.mit.edu/rivest/pubs.html#RR14a

This code simulates an election:
   * defines election ballot style
   * defines number of simulated voters
   * simulates casting of votes
   * creates simulated secure bulletin board
   * posts cast votes on bulletin baord
   * determines election outcome and posts to bulletin baord
   * posts commitments to first part of proof of correct election outcome
   * simulates random "verifier challenges"
   * posts second part of proof of correct election outcome

Implementation features:
  * universally verifiable proof of correctness of election outcome
  * open source (MIT) license
  * multiple races
  * write-in votes

It does not yet simulate:
  * encryption between voter and voting system
  * simulating failure of a server

Modules:
  * sv_main.py            -- top-level module for simulating election
  * sv_verifier.py        -- top-level module for verifying election
  * sv.py                 -- common routines
  * sv_election.py        -- election data structure
  * sv_race.py            -- race data structure
  * sv_voter.py           -- voter data structure and casting votes
  * sv_server.py          -- simulates server array
  * sv_tally.py           -- computes election outcome
  * sv_prover.py          -- produces proof of correctness of outcome
  * sv_sbb.py             -- simulates secure bulletin board  


