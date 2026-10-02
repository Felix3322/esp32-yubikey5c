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
from card_const import KEY_ATTRIBUTES_RSA4K

@pytest.fixture(scope="module",autouse=True)
def check_rsa4k(card):
    print("RSA-4096 keygen")
    if not KEY_ATTRIBUTES_RSA4K in card.supported_key_attrlist[0]:
        pytest.skip("Test for RSA-4096", allow_module_level=True)

from card_test_0_set_attr_rsa4k import *
from card_test_1_keygen import *
from card_test_2_pkop_kg import *
from card_test_3_ds_counter1 import *
