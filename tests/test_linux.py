import os.path
import sys
import unittest
import logging
import json
from layers import VMLayer
from vmtest_helper import LinuxVMTestHelper

class TestLinux(unittest.TestCase):
    domain_name = "nitro_ubuntu1604"
    test_helper = LinuxVMTestHelper
    layer = VMLayer

    def test_handler_control(self):
        """Test bypassing guest's system call handlers"""

        found = False
        unlink_done = False

        def unlink_hook(syscall, backend):
            nonlocal unlink_done
            process = syscall.process
            if process is not None and process.name == "test_unlink_che":
                # If we were really careful we could check that the unlink call was for needle
                # Now we just asume the test binary is not going to call unlink
                unlink_done = True

                logging.debug("unlink hook for test binary called")

                # This works for me but it of course not enough to fully undo effects of SYSCALL
                # I think bunch of registers are still messed up after this

                rcx = syscall.event.get_register("rcx")
                rip = syscall.event.get_register("rip")
                logging.debug("rcx: %s, rip: %s", hex(rcx), hex(rip))
                syscall.event.update_register("rip", rcx)

        def stat_hook(syscall, backend):
            nonlocal found
            process = syscall.process # Process.name isn't the full binary name on Linux
            if process is not None and \
               process.name == "test_unlink_che":
                logging.debug("stat hook for test binary called")
                if unlink_done:
                    if syscall.event.regs.rax == 0:
                        # We managed to bypass the unlink handler
                        logging.debug("stat exited without error: file was not removed")
                        found = True
                    else:
                        logging.debug("stat exitted with an error: file was likely removed")
                
        enter_hooks = {
            "unlink": unlink_hook
        }

        exit_hooks = {
            "newstat": stat_hook
        }

        self.run_binary_test("test_unlink_check_result",
                             enter_hooks=enter_hooks,
                             exit_hooks=exit_hooks)
        self.assertTrue(found)

    def test_open(self):
        """Execute a program that invokes open system call and check that it appears in the event stream"""

        found = False
        needle = "/proc/cpuinfo"

        def open_hook(syscall, backend):
            nonlocal found
            process = syscall.process
            if process is not None and process.name == "test_open":
                path_addr = syscall.args[0]
                path = process.libvmi.read_str_va(path_addr, process.pid)
                logging.debug("open: %s", path)
                if path == needle:
                    found = True

        hooks = {"open": open_hook}
        self.run_binary_test("test_open", hooks)
        self.assertTrue(found)

    def test_write(self):
        """Look for a write system call with a predetermined buffer"""

        last_handle = None
        found = False
        needle = b"Hello World!"

        # This is not really a good strategy
        # We cannot match this system call with the entry and connect path with its fd
        # Now we just hope that the process does not open anything else between this and the write call
        # In this case, it should be fine
        def open_hook(syscall, backend):
            nonlocal last_handle
            process = syscall.process
            if process is not None and process.name == "test_write":
                logging.debug("open returned: %s", syscall.event.regs.rax)
                last_handle = syscall.event.regs.rax

        def write_hook(syscall, backend):
            nonlocal found
            process = syscall.process
            if process is not None and process.name == "test_write":
                handle = syscall.args[0]
                buf_addr = syscall.args[1]
                buf_len = syscall.args[2]
                buf = process.libvmi.read_va(buf_addr, process.pid, buf_len)
                logging.debug("write (handle: %s, buffer size %d): \"%s\"", handle, buf_len, buf)
                if buf == needle and handle == last_handle:
                    found = True
        
        enter_hooks = {"write": write_hook}
        exit_hooks = {"open": open_hook}
        self.run_binary_test("test_write", enter_hooks, exit_hooks)
        self.assertTrue(found)
    
    def test_unlink(self):
        """Look for unlink with predefined path name"""

        found = False
        needle = "/tmp/test_unlink.tmp"

        def unlink_hook(syscall, backend):
            nonlocal found
            process = syscall.process
            if process is not None and process.name == "test_unlink":
                path_addr = syscall.args[0]
                path = process.libvmi.read_str_va(path_addr, process.pid)
                logging.debug("unlink: %s", path)
                if path == needle:
                    found = True

        hooks = {"unlink": unlink_hook}
        self.run_binary_test("test_unlink", hooks)
        self.assertTrue(found)

    def run_binary_test(self, binary, enter_hooks=None, exit_hooks=None):
        binary_path = os.path.join(self.script_dir, "linux_binaries", "build", binary)
        self.vm.cdrom.set_executable(binary_path)

        events, exec_time = self.vm.run_test(enter_hooks=enter_hooks, exit_hooks=exit_hooks)

        with open("{}.json".format(binary), "w") as f:
            json.dump(events, f, indent=4)

        if exec_time is not None:
            logging.info("Test execution time %s", exec_time)

        return events
