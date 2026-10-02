"""
This file has been copied from the Gnuk project.
It did not contain any license or copyright header when it
was copied but we assume that is is distributed under the
GNU General Public Licence version 3 or later (GPLv3+) as
indicated in the Gnuk project README file and that the
copyright holder is Gnuk Author: 
NIIBE Yutaka <gniibe@fsij.org>

Refer to Gnuk source code repository for more information : 
https://salsa.debian.org/gnuk-team/gnuk/gnuk/
"""
import pytest
from card_const import *
from constants_for_test import *

def test_setup_pw1_4(card):
    r = card.change_passwd(1, FACTORY_PASSPHRASE_PW1, PW1_TEST4)
    assert r

def test_verify_pw1_4(card):
    v = card.verify(1, PW1_TEST4)
    assert v

def test_verify_pw1_4_2(card):
    v = card.verify(2, PW1_TEST4)
    assert v
