'''Utilities for system-wide mininet tests.'''

from argparse import ArgumentParser
import difflib, filecmp, os, shlex, shutil, signal, subprocess, sys, tempfile, time
import filecmp, os, pytest

### Fixtures

class InitEnv():
    def __init__(self, benchmark_dir, test_dir):
        self.benchmark_dir = benchmark_dir
        self.test_dir = test_dir

@pytest.fixture(scope="module")
def init():
    '''Delete any old test files and return the name of the test output
    directory.'''
    benchmark_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'regression')
    test_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
    # Check for benchmarks.
    assert os.path.exists(benchmark_dir)
    # Create test dir if not already present.
    if not os.path.exists(test_dir):
        os.mkdir(test_dir)
    # Delete any old test files.
    for f in os.listdir(test_dir):
        if f.endswith(".err") or f.endswith(".out") or f.endswith(".diff"):
            os.remove(os.path.join(test_dir, f))
    return InitEnv(benchmark_dir, test_dir)


### Utility functions

class TestCase():
    def __init__(self, test_name, test_file, test_output_dir, process_mininet_output, process_controller_output, controller_module, controller_opts):
        self.test_name = test_name
        self.test_file = test_file
        self.controller_module = controller_module
        self.test_output_dir = test_output_dir
        self.process_mininet_output = process_mininet_output
        self.process_controller_output = process_controller_output
        self.controller_opts = controller_opts
        self.name = '%s.%s' % (test_name, '.'.join(shlex.split(controller_opts)))
        self.tmpdir = tempfile.mkdtemp()

    def _start_controller(self):
        cmd = ["pyretic.py", self.controller_module, '-v', 'high'] + shlex.split(self.controller_opts)
        out_name = '%s.controller.out' % self.name
        err_name = '%s.controller.err' % self.name
        out_path = os.path.join(self.tmpdir, out_name)
        err_path = os.path.join(self.tmpdir, err_name)
        self.out = file(out_path, 'w')
        self.err = file(err_path, 'w')
        self.process = subprocess.Popen(cmd, stdout=self.out, stderr=self.err) 
        #time.sleep(2)
        return [out_name, err_name]

    def _stop_controller(self):
        self.process.send_signal(signal.SIGINT)
        self.out.close()
        self.err.close()
        #time.sleep(2)

    def _run_mininet(self):
        cmd = shlex.split('sudo %s' % self.test_file)
        out_name = '%s.mininet.out' % self.name
        err_name = '%s.mininet.err' % self.name
        out_path = os.path.join(self.tmpdir, out_name)
        err_path = os.path.join(self.tmpdir, err_name)
        out = file(out_path, 'w')
        err = file(err_path, 'w')
        subprocess.call(cmd, stdout=out, stderr=err)
        out.close()
        err.close()
        return [out_name, err_name]

    def _move_and_filter_result(self, filename, process_output):
        oldfname = os.path.join(self.tmpdir, filename)
        newfname = os.path.join(self.test_output_dir, filename)
        oldf = file(oldfname, 'r')
        newf = file(newfname, 'w')
        process_output(oldf, newf)
        oldf.close()
        newf.close()

    def _cleanup(self):
        subprocess.call(['sudo', 'mn', '-c'])        
        shutil.rmtree(self.tmpdir)

    def run(self):
        controller_files = self._start_controller()
        mininet_files = self._run_mininet()
        self._stop_controller()
        for f in controller_files:
            self._move_and_filter_result(f, self.process_controller_output)
        for f in mininet_files:
            self._move_and_filter_result(f, self.process_mininet_output)
        self._cleanup()
        return [os.path.join(self.test_output_dir, f) for f in mininet_files + controller_files]

class TestModule():
    def __init__(self, 
                 name,
                 filename,
                 get_controller,
                 run_mininet,
                 process_controller_output,
                 process_mininet_output):
        self.name = name
        self.filename = filename
        self.get_controller = get_controller
        self.run_mininet = run_mininet
        self.process_mininet_output = process_mininet_output
        self.process_controller_output = process_controller_output

def run_test(module, test_output_dir, benchmark_dir, controller_args):
    test_name = module.name.split('.')[-1]
    test_file = os.path.abspath(module.filename)
    # Run the test.
    test = TestCase(test_name, test_file, test_output_dir, 
                    module.process_mininet_output, module.process_controller_output,
                    module.get_controller(), controller_args)
    files = test.run()
    files = [os.path.basename(f) for f in files]
    # Compare the output.
    match, mismatch, errors = filecmp.cmpfiles(benchmark_dir, test_output_dir, files)
    if mismatch:
        for fname in mismatch:
            fname1 = os.path.join(benchmark_dir, fname)
            fname2 = os.path.join(test_output_dir, fname)
            diffname = os.path.join(test_output_dir, '%s.diff' % fname)
            f1 = file(fname1, 'r')
            f2 = file(fname2, 'r')
            fdiff = file(diffname, 'w')
            sys.stderr.write('--- Diff: %s vs. %s ---\n' %
              (os.path.basename(fname1), os.path.basename(fname2)))
            d = difflib.Differ()
            diff = difflib.ndiff(f1.readlines(), f2.readlines())
            for line in diff:
                sys.stderr.write(line)
                fdiff.write(line)
            f1.close()
            f2.close()
            fdiff.close()
        assert mismatch == []
    assert errors == []
    assert match == files
