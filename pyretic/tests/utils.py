'''Utilities for system-wide mininet tests.'''

from argparse import ArgumentParser
import difflib, filecmp, os, shlex, shutil, signal, subprocess, sys, tempfile, time

class TestCase():
    def __init__(self, test_name, test_file, test_output_dir, filter_mininet, filter_controller, controller_module, controller_opts):
        self.test_name = test_name
        self.test_file = test_file
        self.controller_module = controller_module
        self.test_output_dir = test_output_dir
        self.filter_mininet = filter_mininet
        self.filter_controller = filter_controller
        self.controller_opts = controller_opts
        self.name = '%s.%s' % (test_name, '.'.join(shlex.split(controller_opts)))
        self.tmpdir = tempfile.mkdtemp()

    def _start_controller(self):
        cmd = ["pyretic.py", self.controller_module] + shlex.split(self.controller_opts)
        out_name = '%s.controller.out' % self.name
        err_name = '%s.controller.err' % self.name
        out_path = os.path.join(self.tmpdir, out_name)
        err_path = os.path.join(self.tmpdir, err_name)
        self.out = file(out_path, 'w')
        self.err = file(err_path, 'w')
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

    def _move_and_filter_result(self, filename, filter_line):
        oldfname = os.path.join(self.tmpdir, filename)
        newfname = os.path.join(self.test_output_dir, filename)
        oldf = file(oldfname, 'r')
        newf = file(newfname, 'w')
        for line in oldf:
            filtered_line = filter_line(line)
            newf.write(filtered_line)
        oldf.close()
        newf.close()

    def _cleanup(self):
        shutil.rmtree(self.tmpdir)

    def run(self):
        controller_files = self._start_controller()
        mininet_files = self._run_mininet()
        self._stop_controller()
        for f in controller_files:
            self._move_and_filter_result(f, self.filter_controller)
        for f in mininet_files:
            self._move_and_filter_result(f, self.filter_mininet)
        self._cleanup()
        return [os.path.join(self.test_output_dir, f) for f in mininet_files + controller_files]

def run_test(module, test_output_dir, benchmark_dir, controller_args):
    test_name = module.__name__.split('.')[-1]
    test_file = os.path.abspath(module.__file__)
    # Run the test.
    test = TestCase(test_name, test_file, test_output_dir, module.filter_mininet, module.filter_controller, module.get_controller(), controller_args)
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

