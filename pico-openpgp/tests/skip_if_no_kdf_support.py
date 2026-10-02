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

@pytest.fixture(scope="module",autouse=True)
def check_kdf_support(card):
    if not card.kdf_supported:
        pytest.skip("No KDF support", allow_module_level=True)
