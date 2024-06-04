const express = require("express");
const qrcode = require("qrcode-terminal");
const dns = require("dns");
const axios = require("axios");

const app = express();
const port = process.env.NODEJS_TOOLS_PORT || 3000;

app.use(express.json());

let bannerCache = {
    welcome: null,
    free: null,
    premium: null,
    trouble: null
};

async function updateBanners() {
    const bannerTypes = ["welcome", "free", "paid", "trouble", "unrecognised_user"];
    for (const type of bannerTypes) {
        const bannerURL = process.env[`${type.toUpperCase()}_BANNER_URL`];
        if (bannerURL) {
            try {
                const response = await axios.get(bannerURL);
                bannerCache[type] = response.data;
            } catch (error) {
                console.error(`Error updating ${type} banner:`, error);
            }
        }
    }
}

setInterval(updateBanners, 60000);

updateBanners();

app.get("/generateQRCode", async (req, res) => {
    const url = req.query.url;

    try {
        if (!url) {
            res.status(400).send("URL is required");
            return;
        }

        const qrCodeText = await generateQRCode(url);

        res.status(200).json({
            qrCodeText: qrCodeText
        });
    } catch (error) {
        console.error("Error generating QR code:", error);
        res.status(500).send("Internal server error");
    }
});

function generateQRCode(url) {
    return new Promise((resolve, reject) => {
        qrcode.generate(url, {
            small: true
        }, (qrcode) => {
            resolve(qrcode);
        });
    });
}

app.get("/getAllInstancesIPv6", async (req, res) => {
    const flydotioAppName = process.env.FLYDOTIO_APP_NAME;

    try {
        const instances = await getAllInstances(flydotioAppName);

        res.status(200).json({
            instances: instances
        });
    } catch (error) {
        console.error("Error getting all instances:", error);
        res.status(500).send("Internal server error");
    }
});

async function getAllInstances(flydotioAppName) {
    try {
        records = await dns.promises.resolve6(`global.${flydotioAppName}.internal`)
    } catch (error) {
        console.log(error);
        return {
            "error": error
        }
    }
    return records;
};

app.get("/addToNginxCache", async (req, res) => {
    const flydotioAppName = process.env.FLYDOTIO_APP_NAME;
    const appname = req.query.app_name;
    const ipv6 = req.query.ipv6;

    try {
        if (!appname) {
            res.status(400).send("app_name is required");
            return;
        }

        if (!ipv6) {
            res.status(400).send("ipv6 is required");
            return;
        }

        const instances = await getAllInstances(flydotioAppName);

        const requests = instances.map(async (instanceIPv6) => {
            const url = `http://[${instanceIPv6}]:8081/cache/add?app_name=${appname}&ipv6=${ipv6}`;
            await axios.get(url);
        });

        await Promise.all(requests);

        res.status(200).json({
            message: "Cache add requests sent successfully",
        });
    } catch (error) {
        console.error("Error updating cache:", error);
        res.status(500).send("Internal server error");
    }
});

app.get("/removeFromNginxCache", async (req, res) => {
    const flydotioAppName = process.env.FLYDOTIO_APP_NAME;
    const appname = req.query.app_name;

    try {
        if (!appname) {
            res.status(400).send("app_name is required");
            return;
        }

        const instances = await getAllInstances(flydotioAppName);

        const requests = instances.map(async (instanceIPv6) => {
            const url = `http://[${instanceIPv6}]:8081/cache/remove?app_name=${appname}`;
            await axios.get(url);
        });

        await Promise.all(requests);

        res.status(200).json({
            message: "Cache remove requests sent successfully",
        });
    } catch (error) {
        console.error("Error updating cache:", error);
        res.status(500).send("Internal server error");
    }
});

app.get("/checkIfTunnelExists", async (req, res) => {
    const flydotioAppName = process.env.FLYDOTIO_APP_NAME;
    const appname = req.query.app_name;

    try {
        if (!appname) {
            res.status(400).send("app_name is required");
            return;
        }

        const instances = await getAllInstances(flydotioAppName);

        let tunnelFound = false;
        let foundIPv6;

        const requests = instances.map(async (instanceIPv6) => {
            const url = `http://[${instanceIPv6}]:8081/check/tunnel?app_name=${appname}`;

            try {
                const response = await axios.get(url);

                if (response.status === 200) {
                    tunnelFound = true;
                    foundIPv6 = instanceIPv6;
                }
            } catch (error) {
                if (error.response && error.response.status === 404) {
                    return;
                }
                throw error;
            }
        });

        await Promise.all(requests);

        if (tunnelFound) {
            res.status(200).json({
                message: "Tunnel found on one of the instances",
                ipv6: foundIPv6
            });
        } else {
            res.status(404).json({
                message: "Tunnel not found on any instance",
            });
        }
    } catch (error) {
        console.error("Error checking tunnel:", error);
        res.status(500).send("Internal server error");
    }
});

app.get("/getBanner", async (req, res) => {
    const type = req.query.type;

    if (bannerCache[type]) {
        res.status(200).json({
            bannerContent: bannerCache[type]
        });
    } else {
        res.status(400).send(`Unhandled banner type: ${type}`);
    }
});

app.get("/keyMatchesAccount", async (req, res) => {
    const {
        username,
        key
    } = req.query;

    try {
        const response = await axios.get(process.env.VERIFY_GITHUB_USER_AND_FETCH_SSH_KEYS_URL, {
            params: {
                username
            },
            headers: {
                Authorization: process.env.ACCESS_TOKEN
            },
            timeout: 10000
        });

        if (response.status === 200) {
            const data = response.data;
            const sshKeys = data.sshKeys || [];
            const isSponsor = data.sponsor || false;

            if (sshKeys.includes(key)) {
                console.log(`The key matches the account ${username}`);
                if (isSponsor) {
                    console.log(`The user ${username} is a sponsor`);
                }
                res.json({
                    matches: true,
                    isSponsor
                });
            } else {
                console.error(`The key does not match the account ${username}`);
                res.json({
                    matches: false,
                    isSponsor
                });
            }
        } else if (response.status === 404) {
            console.log(`The user ${username} is not found as sponsor or stargazer`);
            res.json({
                matches: false,
                isSponsor: false
            });
        }
    } catch (error) {
        console.error(`An error occurred while checking SSH keys for ${username}: ${error}`);
        res.json({
            matches: false,
            isSponsor: false
        });
    }
});

app.get("/isUserSponsor", async (req, res) => {
    const {
        username
    } = req.query;

    try {
        const response = await axios.get(process.env.VERIFY_GITHUB_USER_AND_FETCH_SSH_KEYS_URL, {
            params: {
                username
            },
            headers: {
                Authorization: process.env.ACCESS_TOKEN
            },
            timeout: 10000
        });

        if (response.status === 200) {
            const isSponsor = response.data.sponsor || false;

            if (isSponsor) {
                console.log(`The user ${username} is a sponsor`);
            } else {
                console.log(`The user ${username} is not a sponsor`);
            }
            res.json({
                isSponsor
            });
        } else if (response.status === 404) {
            console.log(`The user ${username} is not a sponsor`);
            res.json({
                isSponsor: false
            });
        }
    } catch (error) {
        console.error(`An error has occurred while checking the status of the user ${username}: ${error}`);
        res.json({
            isSponsor: false
        });
    }
});

app.listen(port, () => {
    console.log(`EXPOSE tools is running on port ${port}`);
});