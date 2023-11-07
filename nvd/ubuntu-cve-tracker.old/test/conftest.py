import os
import pytest
from test_utils import TestUtilities as util

@pytest.fixture(scope="module", autouse=True)
def setup_teardown():
    yield
    for del_file in util.files_to_del:
        if os.path.exists(del_file):
            os.remove(del_file)

