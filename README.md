<h1 align="center">
    <a href="https://expose.sh/#gh-light-mode-only">
    <img src="./.github/assets/expose_logo_black.svg">
    </a>
    <a href="https://expose.sh/#gh-dark-mode-only">
    <img src="./.github/assets/expose_logo_white.svg">
    </a>
</h1>

# EXPOSE-server

## About

EXPOSE-server is the heart of EXPOSE.  
It consists of various programmes that are containerised in a single Docker container and then deployed to machines all over the world using [Fly.io](https://fly.io).
These different programs are :
- An SSH server in Python,
- A Node.js program that acts as an intermediary between the SSH server and the Web server, as well as between remote Web resources and programs in the container,
- A Web server built on OpenResty.

Find out more about EXPOSE by [clicking here](https://expose.sh).

## Deploy

### Generating an SSH key pair

```
ssh-keygen -t ed25519 -f ./ssh_key -N ""
```

### Completing `fly.toml` file

Copy the file `fly.toml.example` to `fly.toml`:

```
cp fly.toml.example fly.toml
```

You need to define the following environment variables:

```
WELCOME_BANNER_URL
FREE_BANNER_URL
PAID_BANNER_URL
TROUBLE_BANNER_URL
UNRECOGNISED_USER_BANNER_URL
VERIFY_GITHUB_USER_AND_FETCH_SSH_KEYS_URL
```

The first four correspond to the banners, and therefore their access link on Google Cloud Storage.  
The last is the link to the Cloud Function that manages user verification.

### Deploying on `fly.io`

Type:

```
fly launch
```

Modify the type of machine as you wish, and enable dedicated IPv4 and IPv6 addresses.

### Adding secrets

First you need to add a secret containing the SSH server's private key:

```
fly secrets set SSH_SERVER_KEY="$(cat ssh_key)"
```

And then the secret containing the access token that enables communication with the Cloud Function:

```
fly secrets set ACCESS_TOKEN=
```

### Pointing domain names to Fly.io's IPv4 and IPv6 addresses

In your registrar's interface, add the IPv4 and IPv6 addresses that Fly.io has assigned to your domain names.

### Add certificates for HTTPS support

In the Fly.io web interface, in the certificate section, add certificates for your domain names (for example: `expose.sh`, `expos.es` and `*.expos.es`).

## More details
### SSH server

The SSH server initializes by loading configurations from environment variables and setting up logging. It checks for the existence of the SSH host key and generates it if necessary. The server creates the UNIX socket directory if it doesn't exist.

The SSH server starts using `asyncssh`, listening for connections on the specified host and port. When a connection is made, it is associated with an IP address and a rate limiter to control excessive connections. Users are authenticated via public keys, verifying if the key matches an authorized account and if they are sponsors. If authenticated and not rate-limited, the server establishes UNIX port forwarding and provides the corresponding internet address.

For each connection, the server generates a unique socket path and manages sponsor or free user files. It adds and removes OpenResty cache entries to manage tunnels. The server limits the number of concurrent connections for free users and automatically disconnects them after a defined period. It regularly checks if a user is still a sponsor and disconnects those who are no longer.

The server sends welcome, unrecognized user, sponsor, or free user banners upon connection. It provides status messages and QR codes for accessing exposed services. Utility functions generate random slugs for connection IDs, manage UNIX socket directories, and handle errors and exceptions to ensure smooth server operation.

### Node.js tools

The Node.js server uses Express to handle HTTP requests and has routes for generating QR codes, managing OpenResty cache, checking tunnels, and verifying user accounts.  
It uses Axios for HTTP requests and DNS promises to resolve IPv6 addresses.  
The server periodically updates banner messages from specified URLs and caches them. It listens on a configurable port and processes JSON request bodies.

The `/generateQRCode` endpoint generates a QR code from a provided URL.  
The `/getAllInstancesIPv6` endpoint retrieves all IPv6 instances of a specified Fly.io app.  
The `/addToNginxCache` and `/removeFromNginxCache` endpoints manage Nginx cache entries for the app across all instances.  
The `/checkIfTunnelExists` endpoint checks if a tunnel exists for a specified app name across instances.  
The `/getBanner` endpoint returns cached banner content based on the requested type.  
The `/keyMatchesAccount` endpoint verifies if a given SSH key matches a GitHub account and checks if the user is a sponsor.  
The `/isUserSponsor` endpoint checks if a GitHub user is a sponsor.

### Web server

The OpenResty configuration manages traffic for various application subdomains, checks for EXPOSE tunnels, and handles caching. The configuration uses all available CPU cores and optimizes connection handling. It handles WebSocket upgrades and sets up a shared cache. It uses Google DNS for resolution.

The first server block listens on port 80 and dynamically routes requests based on the application name subdomain. It checks a cache for backend IPs or fetches them from a local service and updates the cache as needed. It proxies requests to the backend or returns a 404 error if no tunnel is found.

The second server block listens on port 8080 and handles requests to local applications via Unix sockets. It checks if the application is a sponsor and sets a rate limit if not.

The third server block listens on port 8081 and manages cache entries via endpoints for adding and removing cache entries and checks for EXPOSE tunnels.

The fourth and fifth server blocks redirect requests to "expose.sh" and "expos.es" to the project's GitHub page.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see http://www.gnu.org/licenses/.