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
from card_reader import get_ccid_device
from openpgp_card import OpenPGP_Card

def pytest_addoption(parser):
    parser.addoption("--reader", dest="reader", type=str, action="store",
                     default="gnuk", help="specify reader: gnuk or gemalto")

@pytest.fixture(scope="session")
def card():
    print()
    print("Test start!")
    reader = get_ccid_device()
    card = OpenPGP_Card(reader)
    card.cmd_select_openpgp()
    yield card
    del card
    reader.ccid_power_off()
