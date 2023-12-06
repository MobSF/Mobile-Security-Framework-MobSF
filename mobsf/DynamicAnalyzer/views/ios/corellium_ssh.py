# -*- coding: utf_8 -*-
"""Corellium SSH.

Corellium SSH Utilities , modified for MobSF.
Supports SSH over Jump Host
Local Port Forward
Remote Port Forward
SSH Shell Exec
SFTP File Upload
SFTP File Download
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
import io
import logging
import select
import socket
import socketserver
from threading import Thread
from pathlib import Path

import paramiko

from django.conf import settings

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


logger = logging.getLogger(__name__)


def generate_keypair_if_not_exists(location):
    """Generate RSA key pair."""
    prv = location / 'ssh_key.private'
    pub = location / 'ssh_key.public'
    if prv.exists() and pub.exists():
        # Keys Exists
        return prv.read_bytes(), pub.read_bytes()
    logger.info('Generating RSA key pair for Corellium SSH')

    # Generate private/public key pair
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # OpenSSH friendly
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption())

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH)
    prv.write_bytes(private_bytes)
    pub.write_bytes(public_bytes)
    return private_bytes, public_bytes


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


def sock_chan_handler(sock, chan):
    """Socket and Channel Handler."""
    try:
        while True:
            r, w, x = select.select([sock, chan], [], [])
            if sock in r:
                data = sock.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                sock.send(data)
    except ConnectionResetError:
        pass
    finally:
        if chan:
            chan.close()
        if sock:
            sock.close()


# Local Port Forward
class ForwardServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        chan = None
        sock = self.request
        try:
            chan = self.ssh_transport.open_channel(
                'direct-tcpip',
                (self.chain_host, self.chain_port),
                sock.getpeername(),
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
            sock.getpeername(),
            chan.getpeername(),
            (self.chain_host, self.chain_port))
        peername = sock.getpeername()
        sock_chan_handler(sock, chan)
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


# Remote Port Forward
def handler(chan, host, port):
    sock = socket.socket()
    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        # Proxy server is stopped
        return
    except Exception:
        logger.info('Forwarding request to %s:%d failed', host, port)
        return
    sock_chan_handler(sock, chan)


def reverse_forward_tunnel(server_port, remote_host, remote_port, transport):
    try:
        transport.request_port_forward('', server_port)
        while True:
            chan = transport.accept(1000)
            if chan is None:
                continue
            Thread(
                target=handler,
                args=(chan, remote_host, remote_port),
                daemon=True).start()
    except paramiko.SSHException as exp:
        if 'forwarding request denied' in str(exp):
            # Handle TCP forwarding request denied
            # Happens if already forwarding port
            pass
        else:
            logger.exception('SSH Remote Port Forward Exception')


def ssh_jump_host(ssh_string):
    """Connect to SSH over a bastion."""
    ssh_dict = parse_ssh_string(ssh_string)
    bastion_user = ssh_dict['bastion_user']
    bastion_host = ssh_dict['bastion_host']
    user = ssh_dict['private_user']
    private_ip = ssh_dict['private_ip']

    home = Path(settings.UPLD_DIR).parent
    generate_keypair_if_not_exists(home)
    keyf = home / 'ssh_key.private'
    jumpbox = paramiko.SSHClient()
    jumpbox.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    jumpbox.connect(
        bastion_host,
        username=bastion_user,
        key_filename=keyf.as_posix())

    jumpbox_transport = jumpbox.get_transport()
    src_addr = (private_ip, 22)
    dest_addr = (private_ip, 22)
    jumpbox_channel = jumpbox_transport.open_channel(
        'direct-tcpip', dest_addr, src_addr)

    target = paramiko.SSHClient()
    target.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    target.connect(
        private_ip,
        username=user,
        sock=jumpbox_channel,
        password='alpine')
    return target, jumpbox


def ssh_jumphost_port_forward(ssh_string):
    """SSH over Jump Host and Local Port Forward."""
    target, _jumpbox = ssh_jump_host(ssh_string)
    # Frida port
    forward_port = 27042
    remote_host = '127.0.0.1'
    forward_tunnel(
        forward_port,
        remote_host,
        forward_port,
        target.get_transport(),
        ssh_string)


def ssh_jumphost_reverse_port_forward(ssh_string):
    """SSH over Jump Host and Remote Port Forward."""
    target, _jumpbox = ssh_jump_host(ssh_string)
    # HTTPS proxy port
    port = settings.PROXY_PORT
    remote_host = '127.0.0.1'
    reverse_forward_tunnel(
        port,
        remote_host,
        port,
        target.get_transport(),
    )


def ssh_execute_cmd(target, cmd):
    """Execute SSH command."""
    _stdin, _stdout, _stderr = target.exec_command(cmd)
    stdout = _stdout.read().decode(encoding='utf-8', errors='ignore')
    stderr = _stderr.read().decode(encoding='utf-8', errors='ignore')
    return f'{stdout}\n{stderr}'


def ssh_file_upload(ssh_conn_string, fobject, fname):
    """File Upload over SFTP."""
    target, jumpbox = ssh_jump_host(ssh_conn_string)
    with target.open_sftp() as sftp:
        rfile = Path(fname.replace('..', '')).name
        sftp.putfo(fobject, f'/tmp/{rfile}')
    target.close()
    jumpbox.close()


def ssh_file_download(target, remote_path):
    """File Download over SFTP."""
    try:
        with io.BytesIO() as fl:
            with target.open_sftp() as sftp:
                sftp.getfo(remote_path, fl)
                fl.seek(0)
                return fl.read()
    except Exception:
        return None
