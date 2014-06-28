# sv_sbb.py
# python3
# Ronald L. Rivest
# 2014-06-26

""" Code for simulating proof and tally servers for split-vote election.
"""

# MIT open-source license.
# (See https://github.com/ron-rivest/split-value-voting.git)

import time

import sv

class SBB:
    """ Implement secure bulletin board.

    Messages are always lists: [ "msg_type", ... ]
    Convention is that a msg_type starting with "(" is private,
    and not intended to be part of the "public" SBB.  But in this
    code we are using the SBB also a form of event-log, so values
    might be posted here that would not be posted in real election.
    """

    def __init__(self, election_id):
        """ Initialize (simulated) secure bulletin board.
        """

        self.board = []               # list of posted messages
        self.closed = False
        self.start_time = time.time()
        self.post("sbb:open", {"election_id": election_id})

    def close(self):
        """ Close the SBB.  No more posting is allowed. """
        self.post("sbb:close")
        self.closed = True

    def post(self, msg_header, msg_dict=None, time_stamp=True):
        """ Append a message to the sbb.

        Here msg_type is a string, used as a header, and
        msg_dict is a dict with fields for that message.

        Add digital signature here as an option.
        (sign all previous contents of sbb.)
        """

        assert not self.closed
        assert isinstance(msg_header, str)
        if not msg_dict:
            msg_dict = dict()
        assert isinstance(msg_dict, dict)

        assert "time" not in msg_dict
        assert "time_str" not in msg_dict
        if time_stamp:
            # msg_dict['time_seconds'] = time.time()
            msg_dict['time'] = time.strftime("%Y-%m-%dT%H:%M:%S%z")

        if msg_dict:
            msg = [msg_header, msg_dict]
        else:
            msg = [msg_header]
        self.board.append(msg)

    def print_sbb(self, public=True, sbb_filename=None):
        """ Print out contents of sbb to file with name sbb_filename.

        if public is True, then only print out public portion of sbb
        """

        if sbb_filename is None:
            print("Contents of secure bulletin board:")
        else:
            print("Saving contents of secure bulletin board...")

        # if not public and sbb_file is sys.stdout:
        #     print("(lines w/ header in parens are not part of public SBB).")

        board = self.board

        # following not needed in current code:
        if False:
            if public:
                board = [item for item in board if item[0][0] != "("]

        sv.dump(board, sbb_filename)
        if sbb_filename is not None:
            print("Secure bulletin board saved on file:", sbb_filename)

    def hash_sbb(self, public):
        """ Return a (tweaked) hash of the sbb contents. """
        board = self.board
        # next is commented out since we have no no-public posting
        # in the current code.
        if False:
            if public:
                board = [item for item in board if item[0][0] != "("]
        board_str = sv.dumps(board)
        hash_tweak = "hash_sbb"
        return sv.secure_hash(board_str, hash_tweak, iterate=True)






