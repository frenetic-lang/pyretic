'''Utilities for system-wide mininet tests.'''

from argparse import ArgumentParser
import difflib, filecmp, os, shlex, signal, subprocess, sys, time

class TestCase():
    def __init__(self, test_name, test_file, test_output_dir, controller_module, controller_opts):
        self.test_name = test_name
        self.test_file = test_file
        self.controller_module = controller_module
        self.test_output_dir = test_output_dir
        self.controller_opts = controller_opts
        self.name = '%s.%s' % (test_name, '.'.join(shlex.split(controller_opts)))

    def _start_controller(self):
        cmd = ["pyretic.py", self.controller_module] + shlex.split(self.controller_opts)
        out_name = os.path.join(self.test_output_dir, '%s.controller.out' % self.name)
        err_name = os.path.join(self.test_output_dir, '%s.controller.err' % self.name)
        self.out = file(out_name, 'w')
        self.err = file(err_name, 'w')
        self.process = subprocess.Popen(cmd, stdout=self.out, stderr=self.err) 
        time.sleep(2)
        return [out_name, err_name]

    def _stop_controller(self):
        self.process.send_signal(signal.SIGINT)
        self.out.close()
        self.err.close()
        time.sleep(2)

    def _run_mininet(self):
        cmd = shlex.split('sudo %s --mininet' % self.test_file)
        out_name = os.path.join(self.test_output_dir, '%s.mininet.out' % self.name)
        err_name = os.path.join(self.test_output_dir, '%s.mininet.err' % self.name)
        out = file(out_name, 'w')
        err = file(err_name, 'w')
        subprocess.call(cmd, stdout=out, stderr=err)
        out.close()
        err.close()
        return [out_name, err_name]

    def run(self):
        controller_files = self._start_controller()
        mininet_files = self._run_mininet()
        self._stop_controller()
        return mininet_files + controller_files

def run_test(module, test_output_dir, benchmark_dir, controller_args):
    test_name = module.__name__.split('.')[-1]
    test_file = os.path.abspath(module.__file__)
    # Run the test.
    test = TestCase(test_name, test_file, test_output_dir, module.get_controller(), controller_args)
    files = test.run()
    files = [os.path.basename(f) for f in files]
    # Compare the output.
    match, mismatch, errors = filecmp.cmpfiles(benchmark_dir, test_output_dir, files)
    if mismatch:
        for fname in mismatch:
            fname1 = os.path.join(benchmark_dir, fname)
            fname2 = os.path.join(test_output_dir, fname)
            f1 = file(fname1, 'r')
            f2 = file(fname2, 'r')
            sys.stderr.write('--- Diff: %s vs. %s ---\n' % (os.path.basename(fname1), os.path.basename(fname2)))
            d = difflib.Differ()
            diff = difflib.ndiff(f1.readlines(), f2.readlines())
            for line in diff:
                sys.stderr.write(line)
            f1.close()
            f2.close()
        assert mismatch == []
    assert errors == []
    assert match == files

def main(run_mininet):
    # Parse command line args.
    parser = ArgumentParser('Run a Pyretic system test.')
    parser.add_argument("--mininet", action='store_true',
        help="start the mininet for this test")
    args = parser.parse_args()

    if args.mininet:
        run_mininet()
    else:
        print '''This program is intended to be invoked as part of a test suite
        or with the "--mininet" flag to start a mininet instance.  Quitting
        now.'''

