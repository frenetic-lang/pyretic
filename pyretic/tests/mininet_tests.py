
import pyretic.tests.utils as utils
import filecmp, os, pytest

import pyretic.tests.test_hub as test_hub
import pyretic.tests.test_mac_learner as test_mac_learner

### Fixtures

class InitEnv():
    def __init__(self, benchmark_dir, test_dir):
        self.benchmark_dir = benchmark_dir
        self.test_dir = test_dir

@pytest.fixture(scope="module")
def init():
    '''Delete any old test files and return the name of the test output
    directory.'''
    benchmark_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'benchmarks')
    test_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
    # Check for benchmarks.
    assert os.path.exists(benchmark_dir)
    # Create test dir if not already present.
    if not os.path.exists(test_dir):
        os.mkdir(test_dir)
    # Delete any old test files.
    for f in os.listdir(test_dir):
        if f.endswith(".err") or f.endswith(".out"):
            os.remove(os.path.join(test_dir, f))
    return InitEnv(benchmark_dir, test_dir)

### Tests

def test_hub_i(init):
    utils.run_test(test_hub, init.test_dir, init.benchmark_dir, '-m i')
# def test_hub_r0(init):
#      utils.run_test(test_hub, init.test_dir, init.benchmark_dir, '-m r0')
# def test_hub_p0(init):
#     utils.run_test(test_hub, init.test_dir, init.benchmark_dir, '-m p0')
# def test_hub_p1(init):
#     utils.run_test(test_hub, init.test_dir, init.benchmark_dir, '-m p1')

def test_mac_learner_i(init):
    utils.run_test(test_mac_learner, init.test_dir, init.benchmark_dir, '-m i')
def test_mac_learner_r0(init):
    utils.run_test(test_mac_learner, init.test_dir, init.benchmark_dir, '-m r0')
# def test_mac_learner_p0(init):
#     utils.run_test(test_mac_learner, init.test_dir, init.benchmark_dir, '-m p0')
# def test_mac_learner_p1(init):
#     utils.run_test(test_mac_learner, init.test_dir, init.benchmark_dir, '-m p1')

