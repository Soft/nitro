#!/usr/bin/env python3

import re
import psutil
import logging
import time
import threading
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, wait

from enum import Enum

from nitro.event import NitroEvent
from nitro.kvm import KVM, VM

class QEMUNotFoundError(Exception):
    pass

class ContinuationType(Enum):
    DIRECT = 1
    STEP_OVER = 2

def find_qemu_pid(vm_name):
    logging.info('Finding QEMU pid for domain %s', vm_name)
    libvirt_vm_pid_file = '/var/run/libvirt/qemu/{}.pid'.format(vm_name)
    try:
        with open(libvirt_vm_pid_file, 'r') as f:
            content = f.read()
            pid = int(content)
            return pid
    except IOError:
        for proc in psutil.process_iter():
            cmdline = proc.cmdline()[1:]
            if proc.name() == "qemu-system-x86_64" and \
               next((True for k, v in zip(cmdline, cmdline[1:]) if k == "-name" and vm_name in v), False):
                return proc.pid
        logging.critical('Cannot find QEMU')
        raise QEMUNotFoundError('Cannot find QEMU')

class Listener:

    __slots__ = (
        'domain',
        'pid',
        'kvm_io',
        'vm_io',
        'vcpus_io',
        'stop_request',
        'futures',
        'queue',
        'current_cont_queue',
        'current_cont_type'
    )

    def __init__(self, domain):
        self.domain = domain
        self.pid = find_qemu_pid(domain.name())
        # init KVM
        self.kvm_io = KVM()
        # get VM fd
        vm_fd = self.kvm_io.attach_vm(self.pid)
        self.vm_io = VM(vm_fd)
        # get VCPU fds
        self.vcpus_io = self.vm_io.attach_vcpus()
        logging.info('Detected %s VCPUs', len(self.vcpus_io))
        self.stop_request = None
        self.futures = None
        self.queue = None
        self.current_cont_queue = None
        self.current_cont_type = ContinuationType.DIRECT

    def set_traps(self, enabled):
        if self.domain.isActive():
            self.domain.suspend()
            self.vm_io.set_syscall_trap(enabled)
            self.domain.resume()

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.stop()

    def stop(self):
        self.stop_listen()
        self.kvm_io.close()

    def listen(self):
        self.stop_request = threading.Event()
        pool = ThreadPoolExecutor(max_workers=len(self.vcpus_io))
        self.futures = []
        self.queue = Queue(maxsize=1)
        self.current_cont_queue = None
        for vcpu_io in self.vcpus_io:
            # start to listen on this vcpu and report events in the queue
            f = pool.submit(self.listen_vcpu, vcpu_io, self.queue)
            self.futures.append(f)

        # while a thread is still running
        while [f for f in self.futures if f.running()]:
            try:
                (event, continue_queue) = self.queue.get(timeout=1)
            except Empty:
                # domain has crashed or is shutdown ?
                if not self.domain.isActive():
                    self.stop_request.set()
            else:
                self.current_cont_queue = continue_queue
                yield event
                op = self.pop_current_continuation()
                continue_queue.put(op)

        # raise listen_vcpu exceptions if any
        for f in self.futures:
            if f.exception() is not None:
                raise f.exception()
        logging.info('Stop Nitro listening')

    def set_continuation(self, type_):
        self.current_cont_type = type_

    def pop_current_continuation(self):
        op = self.current_cont_type
        # Reset to the default
        self.current_cont_type = ContinuationType.DIRECT
        return op

    def listen_vcpu(self, vcpu_io, queue):
        logging.info('Start listening on VCPU %s', vcpu_io.vcpu_nb)
        # we need a per thread continue event
        continue_queue = Queue(maxsize=1)
        while not self.stop_request.is_set():
            try:
                nitro_raw_ev = vcpu_io.get_event()
            except ValueError as e:
                logging.debug(str(e))
            else:
                e = NitroEvent(nitro_raw_ev, vcpu_io)
                # put the event in the queue
                # and wait for the event to be processed,
                # when the main thread will set the continue_event
                item = (e, continue_queue)
                queue.put(item)
                op = continue_queue.get(True)
                # reset continue_event
                if op == ContinuationType.DIRECT:
                    vcpu_io.continue_vm()
                elif op == ContinuationType.STEP_OVER:
                    vcpu_io.continue_step_over_vm()
                else:
                    raise TypeError("Invalid continuation type")

        logging.debug('stop listening on VCPU %s', vcpu_io.vcpu_nb)

    def stop_listen(self):
        self.set_traps(False)
        self.stop_request.set()
        nb_threads = len([f for f in self.futures if f.running()])
        if nb_threads:
            # ack current thread
            self.current_cont_queue.put(ContinuationType.DIRECT)
            # wait for current thread to terminate
            while [f for f in self.futures if f.running()] == nb_threads:
                time.sleep(0.1)
            # ack the rest of the threads
            while [f for f in self.futures if f.running()]:
                if self.queue.full():
                    (*rest, continue_queue) = self.queue.get()
                    continue_queue.put(ContinuationType.DIRECT)
                # let the threads terminate
                time.sleep(0.1)
            # wait for threads to exit
            wait(self.futures)

    def add_syscall_filter(self, syscall_nb):
        self.vm_io.add_syscall_filter(syscall_nb)

    def remove_syscall_filter(self, syscall_nb):
        self.vm_io.remove_syscall_filter(syscall_nb)
