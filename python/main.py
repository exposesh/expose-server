"""EXPOSE SSH server"""

import asyncio
import logging
import os
import random
import string
import sys
import time
from asyncio import AbstractEventLoop
from collections import deque
from os import path
from types import FrameType
from typing import AnyStr, Optional, Tuple
from _asyncio import Task
from urllib.parse import urlparse

import asyncssh
from asyncssh import SSHKey, SSHServerConnection
from asyncssh.channel import (
    SSHUNIXChannel,
    SSHUNIXSession,
    SSHUNIXSessionFactory,
)
from asyncssh.listener import create_unix_forward_listener
from asyncssh.misc import MaybeAwait
from loguru import logger
from loguru._handler import Handler
import requests
import socket

ssh_host_key = ""

access_token: str = os.getenv("ACCESS_TOKEN", "")
unix_sockets_dir: str = os.getenv("UNIX_SOCKETS_DIRECTORY", "./")
main_url: str = os.getenv("MAIN_URL", "expose.sh")
http_url: str = os.getenv("HTTP_URL", "is-exposed.com")
ssh_server_url: str = os.getenv("SSH_SERVER_URL", "expose.sh")
config_dir: str = os.getenv("CONFIG_DIRECTORY", ".")
rate_limit_count: int = int(os.getenv("RATE_LIMIT_COUNT", "5"))
rate_limit_interval: int = int(os.getenv("RATE_LIMIT_INTERVAL", "60"))
timeout: int = int(os.getenv("TIMEOUT", "120"))
max_free_concurrent_connections: int = int(
    os.getenv("MAX_FREE_CONCURRENT_CONNECTIONS", "2")
)
ssh_server_host: str = os.getenv("SSH_SERVER_HOST", "0.0.0.0")
ssh_server_port: int = int(os.getenv("SSH_SERVER_PORT", "2200"))
ssh_server_key: str = os.getenv("SSH_SERVER_KEY", "")
log_level: str = os.getenv("LOG_LEVEL", "INFO")
log_depth: int = int(os.getenv("LOG_DEPTH", "2"))

key_matches_account_url: str = os.getenv("KEY_MATCHES_ACCOUNT_URL", "http://localhost:3000/keyMatchesAccount")
is_user_sponsor_url: str = os.getenv("IS_USER_SPONSOR_URL", "http://localhost:3000/isUserSponsor")

generate_qrcode_url: str = os.getenv(
    "GENERATE_QRCODE_URL", "http://localhost:3000/generateQRCode"
)
banner_url: str = os.getenv("BANNER_URL", "http://localhost:3000/getBanner")
get_all_instances_ipv6_url: str = os.getenv(
    "GET_ALL_INSTANCES_IPV6_URL", "http://localhost:3000/getAllInstancesIPv6"
)
cache_add_url: str = os.getenv("CACHE_ADD_URL", "http://localhost:3000/addToNginxCache")
cache_remove_url: str = os.getenv(
    "CACHE_REMOVE_URL", "http://localhost:3000/removeFromNginxCache"
)
check_if_tunnel_exists_url: str = os.getenv(
    "CHECK_IF_TUNNEL_EXISTS", "http://localhost:3000/checkIfTunnelExists"
)


def get_ipv6_address(hostname: str) -> Optional[str]:
    try:
        result = socket.getaddrinfo(hostname, None, socket.AF_INET6)
        ipv6_address = result[0][4][0]
        return ipv6_address
    except (socket.gaierror, IndexError) as e:
        print(f"Error retrieving IPv6 address for {hostname}: {e}")
        return None


container_ip = get_ipv6_address("fly-local-6pn")


def key_matches_account(username: str, key: str) -> tuple:
    """Check if a key matches an account using a Cloud Function"""
    try:
        response = requests.get(
            key_matches_account_url, params={"username": username, "key": key}
        )
        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", False)
            is_sponsor = data.get("isSponsor", False)
            if matches:
                logging.info(f"The key matches the account {username}")
                if is_sponsor:
                    logging.info(f"The user {username} is a sponsor")
            else:
                logging.error(f"The key does not match the account {username}")
            return matches, is_sponsor
        else:
            logging.info(f"The user {username} is not found as sponsor or stargazer")
            return False, False
    except requests.exceptions.RequestException as e:
        logging.error(f"An error occurred while checking SSH keys for {username}: {e}")
        return False, False

def is_user_sponsor(username: str) -> bool:
    try:
        response = requests.get(
            is_user_sponsor_url, params={"username": username}
        )
        if response.status_code == 200:
            is_sponsor = response.json().get("isSponsor", False)
            if is_sponsor:
                logging.info(f"The user {username} is a sponsor")
            else:
                logging.info(f"The user {username} is not a sponsor")
            return is_sponsor
        else:
            logging.info(f"The user {username} is not a sponsor")
            return False
    except requests.exceptions.RequestException as e:
        logging.error(
            f"An error has occurred while checking the status of the user {username}: {e}"
        )
        return False


def get_qrcode(url: str) -> str:
    """Get a QR Code using a local web tool"""
    try:
        data = requests.get(generate_qrcode_url, params={"url": url})
        qrcode = data.json().get("qrCodeText", [])

        return qrcode
    except requests.exceptions.RequestException as e:
        logging.error(
            msg=f"An error has occurred while generating QR Code for {url}: {e}"
        )
        return False


def add_to_cache(socket_name: str, ipv6_address: str) -> bool:
    """Add to cache"""
    try:
        response = requests.get(
            cache_add_url,
            params={"app_name": socket_name, "ipv6": ipv6_address},
            timeout=10,
        )
        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        logging.error(f"Error adding to nginx cache: {response.status_code}")
        return False


def remove_from_cache(socket_name: str) -> bool:
    """Remove from cache"""
    try:
        response = requests.get(
            cache_remove_url, params={"app_name": socket_name}, timeout=10
        )
        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        logging.error(f"Error removing from nginx cache: {response.status_code}")
        return False


def check_if_tunnel_exists(socket_name: str) -> bool:
    """Check if tunnel exists"""
    try:
        response = requests.get(
            check_if_tunnel_exists_url, params={"app_name": socket_name}, timeout=10
        )
        if response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking if tunnel exists: {response.status_code}")
        return False


def get_banner(type: str) -> str:
    """Get a banner using a Cloud Function"""
    try:
        data = requests.get(banner_url, params={"type": type})
        banner = data.json().get("bannerContent", [])

        return banner
    except requests.exceptions.RequestException as e:
        logging.error(
            msg=f"An error has occurred while generating banner for {type}: {e}"
        )
        return ""

class RateLimiter:
    """Rate limiter handling class"""

    def __init__(self, max_requests: int, interval: int):
        """Init class"""
        self.max_requests: int = max_requests
        self.interval: int = interval
        self.timestamps: deque = deque()

    def is_rate_limited(self) -> bool:
        """Check if rate limited"""
        now: float = time.time()
        while self.timestamps and self.timestamps[0] < now - self.interval:
            self.timestamps.popleft()
        if len(self.timestamps) >= self.max_requests:
            return True
        self.timestamps.append(now)
        return False


class SSHServer(asyncssh.SSHServer):
    """SSH server protocol handler class"""

    rate_limiters: dict = {}

    def __init__(self):
        """Init class"""
        self.conn: SSHServerConnection
        self.ip_addr: str
        self.socket_paths: dict = {}

    def check_rate_limit(self, ip_addr: str) -> bool:
        """Check if rate limited"""
        if ip_addr not in self.rate_limiters:
            self.rate_limiters[ip_addr] = RateLimiter(
                rate_limit_count, rate_limit_interval
            )
        return self.rate_limiters[ip_addr].is_rate_limited()

    def connection_made(self, conn: SSHServerConnection) -> None:
        """Called when a connection is made"""
        self.conn = conn
        self.ip_addr, _ = conn.get_extra_info("peername")

        if self.check_rate_limit(self.ip_addr):
            conn.set_extra_info(rate_limited=True)

    def public_key_auth_supported(self):
        """Called when a public key authentication request is received"""
        return True

    async def validate_public_key(self, username, key):
        """We use this function to check if a public key matches an account on GitHub"""
        try:
            for key in (
                key.convert_to_public().export_public_key().decode().splitlines()
            ):
                is_key_matching, is_sponsor = key_matches_account(username, key)
                if is_key_matching:
                    self.conn.set_extra_info(key_matching=is_key_matching)
                    self.conn.set_extra_info(sponsor=is_sponsor)
                    break
            if not self.conn.get_extra_info("key_matching"):
                self.conn.set_extra_info(key_matching=False)
                self.conn.set_extra_info(sponsor=False)
            return True
        except:
            self.conn.set_extra_info(key_matching=False)
            self.conn.set_extra_info(sponsor=False)
            return True

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when a connection is lost or closed"""
        if exc:
            logging.info("The connection has been terminated: %s", str(exc))
        try:
            is_sponsor = self.conn.get_extra_info("sponsor")
            if self.socket_paths:
                for socket_path, socket_name in self.socket_paths.items():
                    os.remove(socket_path)
                    if is_sponsor:
                        is_sponsor_file = os.path.join(
                            unix_sockets_dir, f"{socket_name}.sponsor"
                        )
                        os.remove(is_sponsor_file)
                    else:
                        is_free_user_file = os.path.join(
                            unix_sockets_dir, f"{socket_name}.free"
                        )
                        os.remove(is_free_user_file)
                    remove_from_cache(socket_name)
        except:
            pass

    def generate_socket_path(self) -> str:
        """Return the path of a socket whose name has been randomly generated"""
        is_sponsor: bool = self.conn.get_extra_info("sponsor")
        socket_name: str = self.conn.get_extra_info("username")
        free_max_concurrent_connections_reached: bool = False
        self.conn.set_extra_info(
            free_max_concurrent_connections_reached=free_max_concurrent_connections_reached
        )
        if check_if_tunnel_exists(socket_name):
            suffix = 2
            while check_if_tunnel_exists(f"{socket_name}-{suffix}"):
                suffix += 1
                if not is_sponsor and suffix > max_free_concurrent_connections:
                    free_max_concurrent_connections_reached = True
                    self.conn.set_extra_info(
                        free_max_concurrent_connections_reached=free_max_concurrent_connections_reached
                    )
            socket_name = f"{socket_name}-{suffix}"
        self.socket_path = os.path.join(unix_sockets_dir, f"{socket_name}.sock")
        self.socket_paths[self.socket_path] = socket_name
        if is_sponsor:
            is_sponsor_file = os.path.join(unix_sockets_dir, f"{socket_name}.sponsor")
            open(is_sponsor_file, "w").close()
        else:
            is_free_user_file = os.path.join(unix_sockets_dir, f"{socket_name}.free")
            open(is_free_user_file, "w").close()
        add_to_cache(socket_name, container_ip)
        self.conn.set_extra_info(socket_paths=self.socket_paths)
        return self.socket_path

    def server_requested(self, listen_host: str,
                         listen_port: int):
        """Handle a request to listen on a UNIX domain socket"""
        rewrite_path: str = self.generate_socket_path()

        async def tunnel_connection(
            session_factory: SSHUNIXSessionFactory[AnyStr],
        ) -> Tuple[SSHUNIXChannel[AnyStr], SSHUNIXSession[AnyStr]]:
            return await self.conn.create_connection(session_factory, listen_host, listen_port)

        try:
            return create_unix_forward_listener(
                self.conn, asyncio.get_event_loop(), tunnel_connection, rewrite_path
            )
        except OSError as create_unix_forward_listener_exception:
            logging.error(
                "An error occurred while creating the forward listener: %s",
                str(create_unix_forward_listener_exception),
            )

    def unix_server_requested(self, listen_path: str):
        """Handle a request to listen on a UNIX domain socket"""
        rewrite_path: str = self.generate_socket_path()

        async def tunnel_connection(
            session_factory: SSHUNIXSessionFactory[AnyStr],
        ) -> Tuple[SSHUNIXChannel[AnyStr], SSHUNIXSession[AnyStr]]:
            return await self.conn.create_unix_connection(session_factory, listen_path)

        try:
            return create_unix_forward_listener(
                self.conn, asyncio.get_event_loop(), tunnel_connection, rewrite_path
            )
        except OSError as create_unix_forward_listener_exception:
            logging.error(
                "An error occurred while creating the forward listener: %s",
                str(create_unix_forward_listener_exception),
            )


async def handle_ssh_client(process) -> None:
    """Function called every time a client connects to the SSH server"""
    socket_paths: dict = process.get_extra_info("socket_paths")
    rate_limited: bool = process.get_extra_info("rate_limited")
    is_key_matching: bool = process.get_extra_info("key_matching")
    is_sponsor: bool = process.get_extra_info("sponsor")
    username: str = process.get_extra_info("username")
    free_max_concurrent_connections_reached: bool = process.get_extra_info(
        "free_max_concurrent_connections_reached"
    )

    response: str = ""
    welcome_banner: str = get_banner("welcome") + "\n"
    process.stdout.write(welcome_banner + "\n")

    if not is_key_matching:
        unrecognised_user_banner: str = get_banner("unrecognised_user") + "\n"
        process.stdout.write(unrecognised_user_banner + "\n")
        process.logger.info("The user was ejected because the SSH key does not match")
        process.exit(1)
        return

    if not socket_paths:
        response = f"Usage: ssh -R /:host:port {ssh_server_url}\n"
        process.stdout.write(response + "\n")
        process.logger.info(
            "The user was ejected because they did not connect in port forwarding mode"
        )
        process.exit(1)
        return

    if is_sponsor:
        sponsor_banner: str = get_banner("paid") + "\n"
        process.stdout.write(sponsor_banner + "\n")
    else:
        free_banner: str = get_banner("free") + "\n"
        process.stdout.write(free_banner + "\n")

    connection_id: str = time.strftime("%d%m%Y-%H%M-") + get_random_slug(5)
    process.logger.info(f"Connection ID: {connection_id}")
    trouble_banner: str = get_banner("trouble") + connection_id + "\n"
    process.stdout.write(trouble_banner + "\n")

    if free_max_concurrent_connections_reached:
        response = f"The free version of EXPOSE does not allow you to have more than\n{max_free_concurrent_connections} services exposed at the same time.\n"
        process.stdout.write(response + "\n")
        process.logger.info(
            "The user was ejected because they reached the maximum number of connections"
        )
        process.close()

    async def process_timeout(process):
        """Function to terminate the connection automatically
        after a specific period of time (in minutes)"""
        await asyncio.sleep(timeout * 60)
        response = (
            f"Timeout: you were automatically ejected after {timeout} minutes of use.\n"
        )
        process.stdout.write(response + "\n")
        process.logger.info(
            f"The user was automatically ejected after {timeout} minutes of use"
        )
        process.close()

    async def check_if_user_still_sponsor(process):
        """Function to check if the user is still sponsor"""
        while True:
            await asyncio.sleep(120)
            if not is_user_sponsor(username):
                response = "You are no longer a sponsor.\n"
                process.stdout.write(response + "\n")
                process.logger.info(f"The user {username} is no longer a sponsor")
                process.close()

    if not rate_limited:
        for socket_path, socket_name in socket_paths.items():
            no_tls: str = f"{socket_name}.{http_url}"
            tls: str = f"https://{socket_name}.{http_url}"
            qrcode: str = get_qrcode(tls)
            response = f"Internet address: {no_tls}\nTLS termination: {tls}\n{qrcode}"
            process.stdout.write(response + "\n")
            process.logger.info(f"Exposed on {no_tls}")
        if not is_sponsor:
            timeout_task: Task = asyncio.create_task(process_timeout(process))
        else:
            check_premium_task: Task = asyncio.create_task(
                check_if_user_still_sponsor(process)
            )

        while not process.stdin.at_eof():
            try:
                await process.stdin.read()
            except asyncssh.TerminalSizeChanged as exc:
                pass

        if not is_sponsor:
            timeout_task.cancel()
        else:
            check_premium_task.cancel()

        process.exit(0)
    else:
        response = "Rate limited: please try later.\n"
        process.stdout.write(response + "\n")
        process.logger.warning("Rejected connection due to rate limit")
        process.exit(1)
        return


async def start_ssh_server() -> None:
    """Start the SSH server"""
    await asyncssh.create_server(
        SSHServer,
        host=ssh_server_host,
        port=ssh_server_port,
        server_host_keys=[path.join(config_dir, "id_rsa_host")],
        process_factory=handle_ssh_client,
        agent_forwarding=False,
        allow_scp=False,
        server_version=f"EXPOSE SSH Server",
        keepalive_interval=30,
    )
    logging.info("SSH server started successfully.")


def check_unix_sockets_dir() -> None:
    """If the directory for UNIX sockets does not exist, it is created"""
    if not path.exists(unix_sockets_dir):
        os.mkdir(unix_sockets_dir)
        logging.warning(
            "The %s folder does not exist, it has been created.", unix_sockets_dir
        )
    else:
        logging.info("The %s folder exist.", unix_sockets_dir)


class InterceptHandler(logging.Handler):
    """Intercept logging call"""

    def emit(self, record):
        """Find caller from where originated the logged message"""
        frame: FrameType = logging.currentframe()
        depth: int = log_depth
        while frame.f_code.co_filename == logging.__file__:
            frame = frame.f_back
            depth += 1
        logger.opt(exception=record.exc_info).log(log_level, record.getMessage())


def init_logging():
    """Init logging with a custom handler"""
    logging.root.handlers: Handler = [InterceptHandler()]
    logging.root.setLevel(log_level)
    fmt = "<green>[{time}]</green> <level>[{level}]</level> - <level>{message}</level>"
    logger.configure(handlers=[{"sink": sys.stdout, "serialize": False, "format": fmt}])


def get_random_slug(length) -> str:
    """Function that generates a random string of a defined size"""
    chars: str = string.ascii_lowercase + string.digits
    return "".join(random.choices(chars, k=length))


def check_if_ssh_key_exists():
    """Check if the SSH server key exists, if not it is created"""
    ssh_host_key: str = path.join(config_dir, "id_rsa_host")
    if not path.exists(ssh_host_key):
        logging.warning(
            "The SSH server key does not exist, it has been created from env."
        )
        with open(ssh_host_key, "w") as f:
            f.write(ssh_server_key)
        logging.info("The SSH server key has been created.")
    else:
        logging.info("The SSH server key exist.")


if __name__ == "__main__":
    init_logging()
    logging.info("Starting EXPOSE tunnel SSH server...")
    logging.info("Checking if the SSH server key exists...")
    check_if_ssh_key_exists()
    os.umask(0o000)
    logging.info("Checking for the existence of a folder for UNIX sockets...")
    check_unix_sockets_dir()
    loop: AbstractEventLoop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(start_ssh_server())
    except KeyboardInterrupt:
        pass
    except (OSError, asyncssh.Error) as ssh_server_startup_exception:
        logging.critical(
            "An error occurred while starting the SSH server: %s",
            str(ssh_server_startup_exception),
        )
        sys.exit()
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        sys.exit()
