# -*- coding: utf_8 -*-
"""Corellium SSH.

Corellium SSH over Jump Host withLocal Port Forwarding for Frida Connection.
"""
# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.
# Modified for MobSF.

import os
import logging
import socketserver
import select


import paramiko


logger = logging.getLogger(__name__)


def parse_ssh_string(ssh):
    """Parse SSH connection string."""
    ssh_dict = {}
    sp = ssh.split(' ')
    bastion = sp[2]
    private = sp[3]
    ssh_dict['bastion_user'] = bastion.split('@')[0]
    ssh_dict['bastion_host'] = bastion.split('@')[1]
    ssh_dict['private_user'] = private.split('@')[0]
    ssh_dict['private_ip'] = private.split('@')[1]
    return ssh_dict


class ForwardServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        chan = None
        try:
            chan = self.ssh_transport.open_channel(
                'direct-tcpip',
                (self.chain_host, self.chain_port),
                self.request.getpeername(),
            )
        except paramiko.SSHException:
            # SSH tunnel closed, try opening again
            ssh_jumphost_port_forward(self.ssh_string)
        except Exception as e:
            logger.info(
                'Incoming request to %s:%d failed: %s',
                self.chain_host, self.chain_port, repr(e))
            return
        if chan is None:
            logger.info(
                'Incoming request to %s:%d was rejected by the SSH server.',
                self.chain_host, self.chain_port)
            return

        logger.info(
            'Connected!  Tunnel open %r -> %r -> %r',
            self.request.getpeername(),
            chan.getpeername(),
            (self.chain_host, self.chain_port))
        while True:
            r, w, x = select.select([self.request, chan], [], [])
            if self.request in r:
                data = self.request.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                self.request.send(data)

        peername = self.request.getpeername()
        if chan:
            chan.close()
        if self.request:
            self.request.close()
        logger.info('Tunnel closed from %r', peername)


def forward_tunnel(local_port, remote_host, remote_port, transport, ssh):
    # this is a little convoluted, but lets me configure things for the Handler
    # object.  (SocketServer doesn't give Handlers any way to access the outer
    # server normally.)
    class SubHander(Handler):
        chain_host = remote_host
        chain_port = remote_port
        ssh_transport = transport
        ssh_string = ssh

    try:
        ForwardServer(('', local_port), SubHander).serve_forever()
    except OSError:
        logger.info('Port Forwarding Already in place')


def ssh_jump_host(ssh_string):
    """Connect to SSH over a bastion."""
    ssh_dict = parse_ssh_string(ssh_string)
    bastion_user = ssh_dict['bastion_user']
    bastion_host = ssh_dict['bastion_host']
    user = ssh_dict['private_user']
    private_ip = ssh_dict['private_ip']

    jumpbox = paramiko.SSHClient()
    jumpbox.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    jumpbox.connect(bastion_host, username=bastion_user)

    jumpbox_transport = jumpbox.get_transport()
    src_addr = (private_ip, 22)
    dest_addr = (private_ip, 22)
    jumpbox_channel = jumpbox_transport.open_channel(
        'direct-tcpip', dest_addr, src_addr)

    target = paramiko.SSHClient()
    target.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    target.connect(private_ip, username=user, sock=jumpbox_channel)
    return target, jumpbox


def ssh_jumphost_port_forward(ssh_string):
    """SSH over Jump Host and Local Port Forward."""
    target, _jumpbox = ssh_jump_host(ssh_string)
    # Frida port
    forward_port = 27042
    if os.getenv('MOBSF_PLATFORM') == 'docker':
        remote_host = 'host.docker.internal'
    else:
        remote_host = '127.0.0.1'
    forward_tunnel(
        forward_port,
        remote_host,
        forward_port,
        target.get_transport(),
        ssh_string)
    # target close()
    # jumpbox close()


def ssh_execute_cmd(target, cmd):
    """Execute SSH command."""
    _stdin, _stdout, _stderr = target.exec_command(cmd)
    stdout = _stdout.read().decode(encoding='utf-8', errors='ignore')
    stderr = _stderr.read().decode(encoding='utf-8', errors='ignore')
    return f'{stdout}\n{stderr}'