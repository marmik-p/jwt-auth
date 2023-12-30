const { sign, verify } = require("jsonwebtoken");
const { AES, enc } = require("crypto-js");
const moment = require("moment");

/**
 * Generates a JWT token for given payload and options.
 * @param {Object} payload - The payload to be stored in JWT.
 *                           Example: { userId: string, email: string, ... }
 * @param {Object} options - The options object for configuring the token generation.
 *                           Mandatory fields: { JWT_SECRET: string }
 *                           Optional fields: { JWT_SALT?: string, JWT_TOKEN_TYPE?: string, encryptPayload?: boolean, expiry?: number }
 * @returns {string} - The generated JWT token.
 */

const generateJwtToken = (payload, options) => {
    try {
        let userData = payload;
        const { JWT_SECRET, encryptPayload = false, expiry = 2, JWT_TOKEN_TYPE = "ACCESS_TOKEN" } = options;

        // throw error if JWT_SECRET is not available
        if (!JWT_SECRET) throw Error(`JWT_SECRET is required to generate JWT`);
        if (encryptPayload) {
            // encrypt the payload if encryptPayload flag is true
            const { JWT_SALT } = options;
            if (!JWT_SALT) throw Error(`JWT_SALT is required to encrypt payload`);
            userData = AES.encrypt(JSON.stringify(payload), JWT_SALT).toString();
        }

        const expires = moment().add(expiry, "seconds").unix();
        const JwtPayload = {
            sub: userData,
            iat: moment().unix(),
            exp: expires,
            type: JWT_TOKEN_TYPE,
            encryptedPayload: encryptPayload,
        };

        return sign(JwtPayload, JWT_SECRET);
    } catch (err) {
        console.error(`Error in generateJwtToken: ${err}`);
        throw err;
    }
};

/**
 * Verifies and decodes a JWT token using the provided options.
 * @param {string} token - The JWT token to be verified and decoded.
 * @param {Object} options - options: { JWT_SECRET: string, JWT_SALT?: string }
 * @returns {Object|null} - The decoded token payload if verification succeeds, else null.
 */

const verifyToken = (token, options) => {
    try {
        const { JWT_SECRET } = options;
        if (!JWT_SECRET) throw Error(`JWT SECRET is required to decrypt and verify the token`);

        const decryptedToken = verify(token, JWT_SECRET);
        if (!decryptedToken) throw Error(`invalid JWT`);
        let { sub: userData, encryptedPayload } = decryptedToken;

        if (encryptedPayload) {
            const { JWT_SALT } = options;
            if (!JWT_SALT) throw Error(`JWT_SALT is required to decrypt the payload in JWT`);
            const decryptedSub = AES.decrypt(userData, JWT_SALT).toString(enc.Utf8);
            userData = JSON.parse(decryptedSub);
        }

        return userData;
    } catch (error) {
        console.error(`Error in verifyToken: ${error}`);
        throw error;
    }
};

module.exports = {
    generateJwtToken,
    verifyToken,
};
