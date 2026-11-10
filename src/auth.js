const { createRemoteJWKSet, jwtVerify } = require("jose");

const FIREBASE_JWKS_URL =
  "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

/**
 * Verifies a Firebase Auth ID token against Google's public keys, so the API
 * only issues its own JWT to someone who actually signed in with Firebase.
 */
const createFirebaseVerifier = (projectId) => {
  const jwks = createRemoteJWKSet(new URL(FIREBASE_JWKS_URL));
  return async (idToken) => {
    const { payload } = await jwtVerify(idToken, jwks, {
      issuer: `https://securetoken.google.com/${projectId}`,
      audience: projectId,
      algorithms: ["RS256"],
    });
    if (!payload.sub || typeof payload.email !== "string") {
      throw new Error("Identity token has no email");
    }
    return {
      uid: payload.sub,
      email: payload.email.toLowerCase(),
      name: typeof payload.name === "string" ? payload.name : "",
    };
  };
};

module.exports = { createFirebaseVerifier };
