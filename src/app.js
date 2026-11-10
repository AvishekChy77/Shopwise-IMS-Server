const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const { ObjectId } = require("mongodb");
const {
  HttpError,
  SHOP_CATEGORIES,
  FREE_PRODUCT_LIMIT,
  LOW_STOCK_THRESHOLD,
  PLANS,
  computePrices,
  objectId,
  text,
  number,
  oneOf,
  image,
  sameEmail,
  escapeRegex,
  stamp,
} = require("./validate");

// Old payments only carry a "YYYY-MM-DD HH:mm:ss" string; new ones also have createdAt
const PAYMENT_DATE = {
  $ifNull: [
    "$createdAt",
    {
      $dateFromString: {
        dateString: "$date",
        format: "%Y-%m-%d %H:%M:%S",
        timezone: "Asia/Dhaka",
        onError: null,
        onNull: null,
      },
    },
  ],
};

const LOCALHOST = /^http:\/\/localhost:\d+$/;

/**
 * Builds the Express app. Dependencies are injected so the whole API can be
 * exercised against an in-memory database with a fake Stripe client.
 */
function createApp({ db, stripe, verifyIdToken, jwtSecret, allowedOrigins = [] }) {
  if (!jwtSecret) throw new Error("ACCESS_TOKEN_SECRET is not configured");

  const reviews = db.collection("review");
  const users = db.collection("users");
  const shops = db.collection("shops");
  const products = db.collection("products");
  const carts = db.collection("carts");
  const payments = db.collection("payments");
  const notices = db.collection("notices");

  const app = express();
  app.disable("x-powered-by");
  app.use(
    cors({
      origin: (origin, done) =>
        done(null, !origin || allowedOrigins.includes(origin) || LOCALHOST.test(origin)),
    })
  );
  app.use(express.json({ limit: "1mb" }));

  // ---------- auth middleware ----------

  const verifyToken = (req, res, next) => {
    const [scheme, token] = (req.headers.authorization || "").split(" ");
    if (scheme !== "Bearer" || !token) return next(new HttpError(401, "unauthorized access"));
    try {
      req.decoded = jwt.verify(token, jwtSecret, { algorithms: ["HS256"] });
      next();
    } catch {
      next(new HttpError(401, "unauthorized access"));
    }
  };

  const requireRole = (role) => async (req, res, next) => {
    const user = await users.findOne({ email: req.decoded.email });
    if (user?.role !== role) throw new HttpError(403, "forbidden access");
    req.dbUser = user;
    next();
  };
  const verifyManager = requireRole("manager");
  const verifyAdmin = requireRole("admin");

  const ensureSelf = (req, email) => {
    if (!sameEmail(req.decoded.email, email)) throw new HttpError(403, "forbidden access");
  };

  const identify = async (idToken) => {
    if (typeof idToken !== "string" || !idToken) throw new HttpError(400, "idToken is required");
    try {
      return await verifyIdToken(idToken);
    } catch {
      throw new HttpError(401, "Invalid identity token");
    }
  };

  // ---------- public ----------

  app.get("/", (req, res) => res.send("Shopwise is booming"));

  app.get("/health", async (req, res) => {
    const started = Date.now();
    try {
      await db.command({ ping: 1 });
      res.send({ status: "ok", database: "up", latencyMs: Date.now() - started });
    } catch {
      res.status(503).send({ status: "degraded", database: "down" });
    }
  });

  // Exchanges a verified Firebase ID token for the API's own session token
  app.post("/jwt", async (req, res) => {
    const identity = await identify(req.body?.idToken);
    const token = jwt.sign({ email: identity.email }, jwtSecret, { expiresIn: "1h" });
    res.send({ token });
  });

  app.get("/reviews", async (req, res) => {
    res.send(await reviews.find().toArray());
  });

  // ---------- users ----------

  app.post("/users", async (req, res) => {
    const body = req.body || {};
    const identity = await identify(body.idToken);
    const existing = await users.findOne({ email: identity.email });
    if (existing) return res.send({ message: "user already exists", insertedId: null });

    // whitelist fields: role and shop data can never be set from here
    const user = {
      name:
        text(body.name, "Name", { max: 80, required: false }) ||
        identity.name ||
        identity.email.split("@")[0],
      email: identity.email,
      photo: image(body.photo, "Photo"),
      createdAt: new Date(),
    };
    res.send(await users.insertOne(user));
  });

  app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
    res.send(await users.find({}, { projection: { photo: 0 } }).toArray());
  });

  app.get("/users/manager/:email", verifyToken, async (req, res) => {
    ensureSelf(req, req.params.email);
    const user = await users.findOne({ email: req.params.email });
    res.send({ manager: user?.role === "manager" });
  });

  app.get("/users/admin/:email", verifyToken, async (req, res) => {
    ensureSelf(req, req.params.email);
    const user = await users.findOne({ email: req.params.email });
    res.send({ admin: user?.role === "admin" });
  });

  app.get("/users/:email", verifyToken, async (req, res) => {
    if (!sameEmail(req.params.email, req.decoded.email)) {
      const me = await users.findOne({ email: req.decoded.email });
      if (me?.role !== "admin") throw new HttpError(403, "forbidden access");
    }
    res.send(await users.findOne({ email: req.params.email }));
  });

  // Kept for older clients: promotes the caller only if they really own a shop
  app.patch("/users/manager/:email", verifyToken, async (req, res) => {
    ensureSelf(req, req.params.email);
    const shop = await shops.findOne({ email: req.decoded.email });
    if (!shop) throw new HttpError(409, "Create a shop first");
    const result = await users.updateOne(
      { email: req.decoded.email, role: { $ne: "admin" } },
      {
        $set: {
          role: "manager",
          shopId: String(shop._id),
          shopLogo: shop.shopLogo,
          shop: shop.shopName,
        },
      }
    );
    res.send(result);
  });

  // ---------- shops ----------

  app.post("/shops", verifyToken, async (req, res) => {
    const body = req.body || {};
    const email = req.decoded.email;
    const shop = {
      shopName: text(body.shopName, "Shop name", { max: 60 }),
      shopDescription: oneOf(body.shopDescription, SHOP_CATEGORIES, "Category"),
      location: text(body.location, "Location", { max: 120 }),
      shopLogo: image(body.shopLogo, "Shop logo"),
      limit: FREE_PRODUCT_LIMIT,
      email,
      createdAt: new Date(),
    };

    let user = await users.findOne({ email });
    if (user?.role === "admin") throw new HttpError(409, "Admins can't own a shop");
    if (user?.role === "manager" || (await shops.findOne({ email }))) {
      throw new HttpError(409, "You already have a shop");
    }
    const nameTaken = await shops.findOne({
      shopName: { $regex: `^${escapeRegex(shop.shopName)}$`, $options: "i" },
    });
    if (nameTaken) throw new HttpError(409, "That shop name is already taken");

    if (!user) {
      user = { name: email.split("@")[0], email, createdAt: new Date() };
      await users.insertOne(user);
    }
    shop.manager = text(body.manager, "Manager", { max: 80, required: false }) || user.name;

    const result = await shops.insertOne(shop);
    await users.updateOne(
      { email },
      {
        $set: {
          role: "manager",
          shopId: String(result.insertedId),
          shopLogo: shop.shopLogo,
          shop: shop.shopName,
        },
      }
    );
    res.send(result);
  });

  app.get("/shops", verifyToken, verifyAdmin, async (req, res) => {
    const result = await shops
      .aggregate([
        {
          $lookup: {
            from: "products",
            localField: "email",
            foreignField: "email",
            pipeline: [{ $project: { _id: 1 } }],
            as: "items",
          },
        },
        { $addFields: { productCount: { $size: "$items" } } },
        { $project: { items: 0 } },
      ])
      .toArray();
    res.send(result);
  });

  app.get("/shops/:email", verifyToken, verifyManager, async (req, res) => {
    ensureSelf(req, req.params.email);
    res.send(await shops.findOne({ email: req.params.email }));
  });

  // ---------- products ----------

  const readProductFields = (body, { requireImage }) => {
    const productionCost = number(body.productionCost, "Production cost", { max: 10_000_000 });
    const profit = number(body.profit, "Profit margin", { max: 1000 });
    const discount = number(body.discount, "Discount", { max: 100 });
    return {
      productName: text(body.productName, "Product name", { max: 100 }),
      description: text(body.description, "Description", { max: 500 }),
      location: text(body.location, "Location", { max: 120 }),
      quantity: number(body.quantity, "Quantity", { max: 1_000_000, integer: true }),
      productionCost,
      profit,
      discount,
      ...computePrices({ productionCost, profit, discount }),
      img: image(body.img, "Product image", { required: requireImage }),
    };
  };

  app.post("/products", verifyToken, verifyManager, async (req, res) => {
    const fields = readProductFields(req.body || {}, { requireImage: true });
    const email = req.decoded.email;
    const shop = await shops.findOne({ email });
    if (!shop) throw new HttpError(409, "Create a shop first");
    const count = await products.countDocuments({ email });
    if (count >= shop.limit) {
      throw new HttpError(409, "Product limit reached — upgrade your plan to add more");
    }
    const product = {
      ...fields,
      saleCount: 0,
      addingDate: stamp().slice(0, 10),
      shopId: String(shop._id),
      shopName: shop.shopName,
      email,
      createdAt: new Date(),
    };
    res.send(await products.insertOne(product));
  });

  app.get("/products", verifyToken, verifyAdmin, async (req, res) => {
    res.send(await products.find({}, { projection: { img: 0 } }).toArray());
  });

  app.get("/products/:email", verifyToken, verifyManager, async (req, res) => {
    ensureSelf(req, req.params.email);
    const filter = { email: req.params.email };
    const search = typeof req.query.search === "string" ? req.query.search.trim() : "";
    if (search) {
      filter.productName = { $regex: escapeRegex(search.slice(0, 100)), $options: "i" };
    }
    res.send(await products.find(filter).toArray());
  });

  app.patch("/products/:id", verifyToken, verifyManager, async (req, res) => {
    const _id = objectId(req.params.id, "product id");
    const existing = await products.findOne({ _id, email: req.decoded.email });
    if (!existing) throw new HttpError(404, "Product not found");

    const fields = readProductFields(req.body || {}, { requireImage: false });
    if (!fields.img) fields.img = existing.img;
    const result = await products.updateOne({ _id }, { $set: fields });

    // keep pending cart lines in step with the new price and details
    await carts.updateMany(
      { productId: String(_id) },
      {
        $set: {
          productName: fields.productName,
          price: fields.sellingPrice,
          discount: fields.discount,
          img: fields.img,
        },
      }
    );
    res.send(result);
  });

  app.delete("/products/:id", verifyToken, verifyManager, async (req, res) => {
    const _id = objectId(req.params.id, "product id");
    const result = await products.deleteOne({ _id, email: req.decoded.email });
    if (!result.deletedCount) throw new HttpError(404, "Product not found");
    await carts.deleteMany({ productId: String(_id) });
    res.send(result);
  });

  // ---------- carts ----------

  app.post("/carts", verifyToken, verifyManager, async (req, res) => {
    const productId = objectId(req.body?.productId, "product id");
    const email = req.decoded.email;
    const product = await products.findOne({ _id: productId, email });
    if (!product) throw new HttpError(404, "Product not found");

    // each cart line is one unit, so never reserve more than what's on the shelf
    const reserved = await carts.countDocuments({ email, productId: String(productId) });
    if (reserved >= product.quantity) {
      throw new HttpError(
        409,
        product.quantity > 0
          ? "All available stock of this product is already in the cart"
          : "This product is out of stock"
      );
    }
    const item = {
      productId: String(productId),
      img: product.img,
      discount: product.discount,
      productName: product.productName,
      price: product.sellingPrice,
      shopName: product.shopName,
      email,
      addedAt: new Date(),
    };
    res.send(await carts.insertOne(item));
  });

  app.get("/carts/:email", verifyToken, verifyManager, async (req, res) => {
    ensureSelf(req, req.params.email);
    res.send(await carts.find({ email: req.params.email }).toArray());
  });

  app.delete("/carts/:id", verifyToken, verifyManager, async (req, res) => {
    const _id = objectId(req.params.id, "cart item id");
    const result = await carts.deleteOne({ _id, email: req.decoded.email });
    if (!result.deletedCount) throw new HttpError(404, "Cart item not found");
    res.send(result);
  });

  // ---------- payments ----------

  const cartTotal = (items) => items.reduce((sum, i) => sum + (Number(i.price) || 0), 0);

  // The amount is always computed here; the client never says what to charge
  app.post("/create-payment-intent", verifyToken, verifyManager, async (req, res) => {
    const body = req.body || {};
    const email = req.decoded.email;
    let amount;
    let currency;
    let metadata;

    if (body.type === "subscription") {
      const plan = PLANS[body.plan];
      if (!plan) throw new HttpError(400, "Unknown plan");
      amount = plan.price * 100;
      currency = "usd";
      metadata = { type: "subscription", plan: body.plan, email };
    } else {
      const items = await carts.find({ email }).toArray();
      if (!items.length) throw new HttpError(409, "Your cart is empty");
      amount = Math.round(cartTotal(items) * 100);
      currency = "bdt";
      metadata = { type: "sale", email };
    }

    let intent;
    try {
      intent = await stripe.paymentIntents.create({
        amount,
        currency,
        payment_method_types: ["card"],
        metadata,
      });
    } catch (err) {
      throw new HttpError(400, err?.message || "Could not start the payment");
    }
    res.send({ clientSecret: intent.client_secret, amount: amount / 100, currency });
  });

  const loadSucceededIntent = async (id, type, email) => {
    if (typeof id !== "string" || !/^pi_[A-Za-z0-9]+$/.test(id)) {
      throw new HttpError(400, "Invalid transaction id");
    }
    if (await payments.findOne({ transcationId: id })) {
      throw new HttpError(409, "This payment was already recorded");
    }
    let intent;
    try {
      intent = await stripe.paymentIntents.retrieve(id);
    } catch {
      throw new HttpError(400, "Payment not found");
    }
    if (intent.status !== "succeeded") throw new HttpError(402, "Payment has not completed");
    if (intent.metadata?.type !== type || !sameEmail(intent.metadata?.email, email)) {
      throw new HttpError(400, "Payment does not match this request");
    }
    return intent;
  };

  app.post("/payments", verifyToken, verifyManager, async (req, res) => {
    const email = req.decoded.email;
    const intent = await loadSucceededIntent(req.body?.transcationId, "sale", email);

    const items = await carts.find({ email }).toArray();
    const total = cartTotal(items);
    if (!items.length || Math.round(total * 100) !== intent.amount) {
      throw new HttpError(409, "Cart changed after the payment started — contact support");
    }

    const now = new Date();
    const payment = {
      type: "sale",
      email,
      price: total,
      transcationId: intent.id,
      date: stamp(now),
      timecount: now.getTime(),
      createdAt: now,
      cartIds: items.map((i) => String(i._id)),
      productIds: items.map((i) => new ObjectId(i.productId)),
      status: "success",
    };
    const paymentResult = await payments.insertOne(payment);
    const deleteResult = await carts.deleteMany({ _id: { $in: items.map((i) => i._id) } });

    const units = new Map();
    for (const id of payment.productIds) units.set(String(id), (units.get(String(id)) || 0) + 1);
    await Promise.all(
      [...units].map(([id, n]) =>
        products.updateOne({ _id: new ObjectId(id), email }, [
          {
            $set: {
              saleCount: { $add: [{ $ifNull: ["$saleCount", 0] }, n] },
              quantity: { $max: [0, { $subtract: ["$quantity", n] }] },
            },
          },
        ])
      )
    );
    res.send({ paymentResult, deleteResult });
  });

  app.post("/payments/subscription", verifyToken, verifyManager, async (req, res) => {
    const email = req.decoded.email;
    const intent = await loadSucceededIntent(req.body?.transcationId, "subscription", email);
    const plan = PLANS[intent.metadata.plan];
    if (!plan) throw new HttpError(400, "Unknown plan");
    const shop = await shops.findOne({ email });
    if (!shop) throw new HttpError(409, "Create a shop first");

    const now = new Date();
    const payment = {
      type: "subscription",
      email,
      plan: intent.metadata.plan,
      price: plan.price,
      limit: plan.limit,
      shopName: shop.shopName,
      transcationId: intent.id,
      status: "success",
      date: stamp(now),
      timecount: now.getTime(),
      createdAt: now,
    };
    const paymentResult = await payments.insertOne(payment);
    const shopResult = await shops.updateOne({ _id: shop._id }, { $inc: { limit: plan.limit } });
    res.send({ paymentResult, shopResult });
  });

  app.get("/payments/:email", verifyToken, verifyManager, async (req, res) => {
    ensureSelf(req, req.params.email);
    const result = await payments
      .aggregate([
        { $match: { email: req.params.email, productIds: { $exists: true } } },
        { $unwind: "$productIds" },
        {
          $lookup: {
            from: "products",
            localField: "productIds",
            foreignField: "_id",
            pipeline: [{ $project: { img: 0 } }],
            as: "productlists",
          },
        },
        { $unwind: "$productlists" },
        { $addFields: { sortDate: PAYMENT_DATE } },
        { $sort: { sortDate: -1 } },
        { $project: { sortDate: 0 } },
      ])
      .toArray();
    res.send(result);
  });

  // ---------- dashboard stats ----------

  const salesPipeline = (match, extraFacets) => [
    { $match: { ...match, productIds: { $exists: true } } },
    { $addFields: { paidAt: PAYMENT_DATE } },
    { $unwind: "$productIds" },
    {
      $lookup: {
        from: "products",
        localField: "productIds",
        foreignField: "_id",
        pipeline: [{ $project: { productName: 1, sellingPrice: 1, productionCost: 1, shopName: 1 } }],
        as: "p",
      },
    },
    { $unwind: "$p" },
    {
      $facet: {
        totals: [
          {
            $group: {
              _id: null,
              orders: { $addToSet: "$_id" },
              unitsSold: { $sum: 1 },
              revenue: { $sum: "$p.sellingPrice" },
              cost: { $sum: "$p.productionCost" },
            },
          },
        ],
        ...extraFacets,
      },
    },
  ];

  app.get("/stats/manager", verifyToken, verifyManager, async (req, res) => {
    const email = req.decoded.email;
    const year = Number(stamp().slice(0, 4));

    const [shop, inventory, lowStock, salesAgg] = await Promise.all([
      shops.findOne({ email }, { projection: { limit: 1 } }),
      products
        .aggregate([
          { $match: { email } },
          {
            $group: {
              _id: null,
              products: { $sum: 1 },
              unitsInStock: { $sum: "$quantity" },
              outOfStock: { $sum: { $cond: [{ $lte: ["$quantity", 0] }, 1, 0] } },
              stockValue: { $sum: { $multiply: ["$quantity", "$productionCost"] } },
            },
          },
        ])
        .toArray(),
      products
        .find(
          { email, quantity: { $lte: LOW_STOCK_THRESHOLD } },
          { projection: { productName: 1, quantity: 1 } }
        )
        .sort({ quantity: 1 })
        .limit(10)
        .toArray(),
      payments
        .aggregate(
          salesPipeline(
            { email },
            {
              monthly: [
                {
                  $match: {
                    $expr: {
                      $eq: [{ $year: { date: "$paidAt", timezone: "Asia/Dhaka" } }, year],
                    },
                  },
                },
                {
                  $group: {
                    _id: { $month: { date: "$paidAt", timezone: "Asia/Dhaka" } },
                    units: { $sum: 1 },
                    revenue: { $sum: "$p.sellingPrice" },
                  },
                },
              ],
              topProducts: [
                {
                  $group: {
                    _id: "$p._id",
                    productName: { $first: "$p.productName" },
                    unitsSold: { $sum: 1 },
                    revenue: { $sum: "$p.sellingPrice" },
                  },
                },
                { $sort: { unitsSold: -1, revenue: -1 } },
                { $limit: 5 },
              ],
            }
          )
        )
        .toArray(),
    ]);

    const inv = inventory[0] || {};
    const sales = salesAgg[0];
    const t = sales.totals[0] || {};
    res.send({
      year,
      productLimit: shop?.limit ?? null,
      inventory: {
        products: inv.products || 0,
        unitsInStock: inv.unitsInStock || 0,
        outOfStock: inv.outOfStock || 0,
        stockValue: inv.stockValue || 0,
        lowStockThreshold: LOW_STOCK_THRESHOLD,
        lowStock,
      },
      sales: {
        orders: t.orders?.length || 0,
        unitsSold: t.unitsSold || 0,
        revenue: t.revenue || 0,
        profit: (t.revenue || 0) - (t.cost || 0),
        monthly: Array.from({ length: 12 }, (_, i) => {
          const row = sales.monthly.find((m) => m._id === i + 1);
          return { month: i + 1, units: row?.units || 0, revenue: row?.revenue || 0 };
        }),
        topProducts: sales.topProducts.map(({ _id, ...rest }) => ({ productId: _id, ...rest })),
      },
    });
  });

  app.get("/stats/admin", verifyToken, verifyAdmin, async (req, res) => {
    const [shopCount, userCount, managerCount, inventory, salesAgg, subs] = await Promise.all([
      shops.countDocuments(),
      users.countDocuments(),
      users.countDocuments({ role: "manager" }),
      products
        .aggregate([
          {
            $group: { _id: null, products: { $sum: 1 }, unitsInStock: { $sum: "$quantity" } },
          },
        ])
        .toArray(),
      payments
        .aggregate(
          salesPipeline(
            {},
            {
              topShops: [
                {
                  $group: {
                    _id: "$p.shopName",
                    unitsSold: { $sum: 1 },
                    revenue: { $sum: "$p.sellingPrice" },
                  },
                },
                { $sort: { revenue: -1 } },
                { $limit: 5 },
              ],
            }
          )
        )
        .toArray(),
      payments
        .aggregate([
          { $match: { limit: { $exists: true } } },
          { $group: { _id: null, count: { $sum: 1 }, revenue: { $sum: "$price" } } },
        ])
        .toArray(),
    ]);

    const t = salesAgg[0].totals[0] || {};
    res.send({
      shops: shopCount,
      users: userCount,
      managers: managerCount,
      products: inventory[0]?.products || 0,
      unitsInStock: inventory[0]?.unitsInStock || 0,
      sales: {
        currency: "BDT",
        orders: t.orders?.length || 0,
        unitsSold: t.unitsSold || 0,
        revenue: t.revenue || 0,
      },
      subscriptions: {
        currency: "USD",
        count: subs[0]?.count || 0,
        revenue: subs[0]?.revenue || 0,
      },
      topShops: salesAgg[0].topShops.map(({ _id, ...rest }) => ({ shopName: _id, ...rest })),
    });
  });

  // ---------- notices (admin -> shop manager) ----------

  app.post("/notices", verifyToken, verifyAdmin, async (req, res) => {
    const body = req.body || {};
    const email = text(body.email, "Recipient", { max: 254 }).toLowerCase();
    const shop = await shops.findOne({ email });
    if (!shop) throw new HttpError(404, "No shop found for that manager");
    const notice = {
      email,
      shopName: shop.shopName,
      title: text(body.title, "Title", { max: 100 }),
      message: text(body.message, "Message", { max: 1000 }),
      from: req.decoded.email,
      read: false,
      createdAt: new Date(),
    };
    res.send(await notices.insertOne(notice));
  });

  app.get("/notices", verifyToken, async (req, res) => {
    const list = await notices
      .find({ email: req.decoded.email })
      .sort({ createdAt: -1 })
      .limit(50)
      .toArray();
    res.send({ unread: list.filter((n) => !n.read).length, notices: list });
  });

  app.patch("/notices/:id/read", verifyToken, async (req, res) => {
    const _id = objectId(req.params.id, "notice id");
    const result = await notices.updateOne(
      { _id, email: req.decoded.email },
      { $set: { read: true, readAt: new Date() } }
    );
    if (!result.matchedCount) throw new HttpError(404, "Notice not found");
    res.send(result);
  });

  // ---------- fallbacks ----------

  app.use((req, res) => res.status(404).send({ message: "Not found" }));

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    const status = err.status || err.statusCode;
    if (status && status < 500) {
      const message =
        err.type === "entity.parse.failed"
          ? "Malformed JSON body"
          : err.type === "entity.too.large"
          ? "Request is too large"
          : err.message;
      return res.status(status).send({ message });
    }
    console.error(err);
    res.status(500).send({ message: "Something went wrong" });
  });

  return app;
}

module.exports = createApp;
