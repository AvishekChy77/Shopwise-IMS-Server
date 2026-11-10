require("dotenv").config();
const { MongoClient, ServerApiVersion } = require("mongodb");
const Stripe = require("stripe");
const createApp = require("./src/app");
const { createFirebaseVerifier } = require("./src/auth");

const uri =
  process.env.MONGODB_URI ||
  `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.jtchhsy.mongodb.net/?retryWrites=true&w=majority`;

// The driver connects lazily on the first query, which suits serverless cold starts
const client = new MongoClient(uri, { serverApi: { version: ServerApiVersion.v1 } });

const DEFAULT_ORIGINS = ["https://shopwise-im.web.app", "https://shopwise-im.firebaseapp.com"];
const extraOrigins = (process.env.CLIENT_ORIGINS || "")
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

const app = createApp({
  db: client.db("ShopwiseDB"),
  stripe: Stripe(process.env.STRIPE_SECRET_KEY),
  verifyIdToken: createFirebaseVerifier(process.env.FIREBASE_PROJECT_ID || "shopwise-im"),
  jwtSecret: process.env.ACCESS_TOKEN_SECRET,
  allowedOrigins: [...DEFAULT_ORIGINS, ...extraOrigins],
});

if (require.main === module) {
  const port = process.env.PORT || 5000;
  app.listen(port, () => console.log(`Shopwise is running on port ${port}`));
}

module.exports = app;
