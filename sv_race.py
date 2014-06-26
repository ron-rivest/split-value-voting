# race.py
# python3
# Ronald L. Rivest
# 2014-06-13

""" Prototype code implementing a race in split-value voting method
    This code is meant to be pedagogic and illustrative of main concepts;
    many details would need adjustment or filling in for a final implementation.
"""

# MIT open-source license.
# (See https://github.com/ron-rivest/split-value-voting.git)

import sv

# Standard list of write-in candidates to use (max 13 char)
WRITE_INS = ["Donald Duck",
             "Lizard People",
             "Mickey Mouse"]

class Race:
    """ Implements a race in a split-value voting method. """

    def __init__(self, election, race_id, choices):
        """ Initialize race

            race_id is a string
            choices is list consisting of
               one string for each allowable candidate/choice name
               a string "************************" of stars
                  of the maximum allowable length of a write-in
                  if write-ins are allowed.
            Example:
              race_id = "President"
              choices =  ("Smith", "Jones", "********")
                 defines a race (for President), and
                 for this race the voter may vote for Smith, for Jones, or
                 may cast a write-in vote of length at most 8 characters.
        """

        assert isinstance(race_id, str) and len(race_id) > 0

        assert isinstance(choices, (list, tuple)) and len(choices) > 0
        # must be more than one choice, except if sole choice is for write-ins
        assert len(choices) > 1 or choices[0] in "*"*1000
        # choices must be distinct
        assert len(choices) == len(set(choices))
        # choices must be strings
        assert all([isinstance(choice, str) for choice in choices])

        self.election = election
        self.race_id = race_id
        self.choices = choices

        # set race.race_modulus = modulus for representing choices in this race.
        # note that for computation and comparison purposes, choices will
        # be converted to type bytes
        # make race_modulus a prime big enough to encode all possible choices
        self.max_choice_len = max([len(choice.encode()) for choice in choices])
        self.race_modulus = sv.make_prime(256**self.max_choice_len)

        self.tally = None

        rand_name = "random:"+race_id               # only for simulation
        self.rand_name = rand_name
        sv.init_randomness_source(rand_name)

    def random_choice(self):
        """ Return a random choice for this race.

        If write-ins are allowed, then pick a write_in from
        a small built-in list of alternatives.
        """

        choice_index = sv.get_random_from_source(self.rand_name,
                                                 len(self.choices))
        choice = self.choices[choice_index]
        all_stars = all([c == "*" for c in choice])
        if not all_stars:
            return choice
        # select write_in from fixed list of alternatives
        # but truncate if needed so it is not longer than list of stars
        max_len_write_in = len(choice)
        index = sv.get_random_from_source(self.rand_name, len(WRITE_INS))
        choice = WRITE_INS[index][:max_len_write_in]
        return choice

    def is_valid_choice(self, choice):
        """ Return True if and only choice is a valid one for this race. """
        assert isinstance(choice, str)
        if choice in self.choices:
            return True
        for valid_choice in self.choices:
            if all([c == "*" for c in valid_choice]):
                if len(choice) <= len(valid_choice):
                    return True
        return False

    def choice_str2int(self, choice_str):
        """ Convert choice_str (a string) to an integer modulo race_modulus. """
        assert isinstance(choice_str, str)
        choice_bytes = choice_str.encode()           # convert to bytes
        choice_int = sv.bytes2int(choice_bytes)      # convert to int
        assert 0 <= choice_int < self.race_modulus
        return choice_int

    def choice_int2str(self, choice_int):
        """ Inverse of choice_str2int; convert integer to choice string. """
        assert isinstance(choice_int, int) and \
            0 <= choice_int < self.race_modulus
        choice_bytes = sv.int2bytes(choice_int)
        choice_str = choice_bytes.decode()
        assert self.is_valid_choice(choice_str)
        return choice_str




