# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import division

"""
LELEC2770 : Privacy Enhancing Technologies

Exercice Session : Secure 2-party computation

Oblivious Transfer
"""

from Crypto.Random import random

from elgamal import elgamal_param_gen
from aes import AES_key


class Sender(object):
    """Oblblivious transfer sender for AES keys

    :param msg_0: Message 0
    :param msg_1: Message 1
    :type msg_0: AES_key
    :type msg_1: AES_key
    """

    def __init__(self, msg_0, msg_1):
        assert isinstance(msg_0, AES_key)
        assert isinstance(msg_1, AES_key)
        self.m_0 = msg_0  # must be aes key
        self.m_1 = msg_1  # must be aes key

    def response(self, c, pk):
        """Response to a challenge sent by the receiver

        :param c: Encrypted challenge
        :param pk: Encryption public key
        :type c: ElgamalCiphertext
        :type pk: ElgamalPublicKey
        :return: Encrypted responses c_0, c_1
        :rtype: (ElgamalCiphertext, ElgamalCiphertext)
        """
        # **********************************************************************
        # Exercise 1
        # ==========
        # <To be done by students>
        # c = Enc_pk(b) (first input of this method)
        r_0 = pk.random()
        r_1 = pk.random()
        enc_1 = pk.encrypt(1)
        # from the slides:
        #   c_0 = Enc_pk((1-b) * x_0 + r_0 * b)
        c_0 = ((enc_1 - c) * self.m_0.as_int()) + (r_0 * c)
        # from the slides:
        #   c_1 = Enc_pk(b * x_1 + r_1 * (1-b))
        c_1 = (c * self.m_1.as_int()) + (r_1 * (enc_1 - c))
        # </To be done by students>
        # **********************************************************************
        return c_0, c_1


class Receiver(object):
    """Oblivious transfer receiver for AES keys

    Attributes:
    * pk: Public key
    * sk: Secret key
    """

    def __init__(self):
        self.pk, self.sk = elgamal_param_gen()

    def challenge(self, b):
        """Generate an OT challenge

        :param b: Message to receive (0 or 1)
        :type b: int
        :return: OT challenge
        :rtype: ElgamalCiphertext
        """
        # **********************************************************************
        # Exercise 1
        # ==========
        # <To be done by students>
        return self.pk.encrypt(b)
        # </To be done by students>
        # **********************************************************************

    def decrypt_response(self, c_0, c_1, b):
        """Decrypt response received from Sender

        :param c_0: Response part 0
        :param c_1: Response part 1
        :type c_0: ElgamalCiphertext
        :type c_1: ElgamalCiphertext
        :return: Transferred message
        :rtype: AES_key
        """
        # **********************************************************************
        # Exercise 1
        # ==========
        # <To be done by students>
        m = self.sk.decrypt([c_0, c_1][b])
        # </To be done by students>
        # **********************************************************************
        key = AES_key.from_int(m)
        return key


def test_OT():
    # See slides "Secure Computation" - 24:
    # initialize [R]eceiver
    Bob = Receiver()
    # initialize [S]ender with (x0, x1) to be sent to R
    x_0 = AES_key.gen_random()
    x_1 = AES_key.gen_random()
    Alice = Sender(x_0, x_1)
    # start the protocol
    # 1) R sends pk,Enc_pk(b) to S
    b = random.getrandbits(1)
    pk = Bob.pk
    c = Bob.challenge(b)
    # 2) S sends (c_0,c_1) to R
    c_0, c_1 = Alice.response(c, pk)
    # 3) R can now select the right c_i with b and get mb by decrypting it with
    #    its secret key
    x = Bob.decrypt_response(c_0, c_1, b)
    # protocol over ; now verify the result
    assert (x_0, x_1)[b] == x
    #print(x_0.as_int(), x_1.as_int(), b, x.as_int())


if __name__ == "__main__":
    test_OT()
