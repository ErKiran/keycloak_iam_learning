const querystring = require("querystring");
const axios = require("axios");
const jwt = require("jsonwebtoken")
const {
    KEYCLOAK_CLIENT_ID,
    KEYCLOAK_CLIENT_SECRET,
    REDIRECT_URI,
    authorizeEndpoint,
    tokenEndpoint } = require("../helper")

function login(req, res) {
    const authUrl =
        `${authorizeEndpoint}?` +
        querystring.stringify({
            client_id: KEYCLOAK_CLIENT_ID,
            response_type: "code",
            scope: "openid profile email",
            redirect_uri: REDIRECT_URI,
        });

    res.render("login", { authUrl })
};

async function callback(req, res) {
    const { code } = req.query;

    if (!code) {
        return res.status(400).send("Missing authorization code");
    }

    console.log("code\t", code)

    try {
        const tokenResponse = await axios.post(
            tokenEndpoint,
            querystring.stringify({
                grant_type: "authorization_code",
                code: code,
                redirect_uri: REDIRECT_URI,
            }),
            {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    // Real-world: client authentication via Basic Auth header
                    Authorization:
                        "Basic " +
                        Buffer.from(
                            `${KEYCLOAK_CLIENT_ID}:${KEYCLOAK_CLIENT_SECRET}`
                        ).toString("base64"),
                },
            }
        );

        const tokens = tokenResponse.data;

        // Store tokens in session
        req.session.tokens = tokens;

        // Decode ID token just for display (not verifying signature here)
        const decoded = tokens.id_token ? jwt.decode(tokens.id_token) : null;

        req.session.user = {
            username: decoded?.preferred_username || decoded?.email || "user",
            name: decoded?.name || null,
            email: decoded?.email || null,
        };

        // Default mock balance
        req.session.balance = req.session.balance ?? 1000;

        if (req.session.pendingTransfer) {
            req.session.transferAllowed = true;
            return res.redirect("/resume-transfer");
        }

        return res.redirect("/dashboard");

    } catch (err) {
        console.error(err.response?.data || err.message);
        res.status(500).send("Token exchange failed");
    }
}
module.exports = { login, callback }