const { ObjectId } = require("mongodb");

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// Business rules shared by several routes
const SHOP_CATEGORIES = [
  "Apparel",
  "Bike",
  "Electronics",
  "Home Decor",
  "Gift Store",
  "Health & Beauty",
];
const FREE_PRODUCT_LIMIT = 3;
const LOW_STOCK_THRESHOLD = 5;
const PLANS = {
  standard: { name: "Standard Pack", price: 10, limit: 200 },
  medium: { name: "Medium Pack", price: 20, limit: 450 },
  heavy: { name: "Heavy Pack", price: 50, limit: 1500 },
};

// 7.5% platform charge is added on top of the profit margin
const computePrices = ({ productionCost, profit, discount }) => {
  const listPrice = Math.trunc(productionCost + (productionCost * (profit + 7.5)) / 100);
  const sellingPrice = Math.trunc(listPrice - (listPrice * discount) / 100);
  return { listPrice, sellingPrice };
};

const objectId = (value, label = "id") => {
  if (typeof value !== "string" || !/^[a-f\d]{24}$/i.test(value)) {
    throw new HttpError(400, `Invalid ${label}`);
  }
  return new ObjectId(value);
};

const text = (value, label, { max = 200, required = true } = {}) => {
  const v = typeof value === "string" ? value.trim() : "";
  if (!v && required) throw new HttpError(400, `${label} is required`);
  if (v.length > max) throw new HttpError(400, `${label} must be at most ${max} characters`);
  return v;
};

const number = (value, label, { min = 0, max = Number.MAX_SAFE_INTEGER, integer = false } = {}) => {
  const n = typeof value === "string" && value.trim() !== "" ? Number(value) : value;
  if (typeof n !== "number" || !Number.isFinite(n)) throw new HttpError(400, `${label} must be a number`);
  if (integer && !Number.isInteger(n)) throw new HttpError(400, `${label} must be a whole number`);
  if (n < min || n > max) throw new HttpError(400, `${label} must be between ${min} and ${max}`);
  return n;
};

const oneOf = (value, allowed, label) => {
  if (!allowed.includes(value)) throw new HttpError(400, `${label} must be one of: ${allowed.join(", ")}`);
  return value;
};

// Images arrive as compressed data URLs from the client, or as legacy URLs
const MAX_IMAGE_LENGTH = 700_000;
const image = (value, label, { required = false } = {}) => {
  const v = typeof value === "string" ? value.trim() : "";
  if (!v) {
    if (required) throw new HttpError(400, `${label} is required`);
    return "";
  }
  if (v.length > MAX_IMAGE_LENGTH) throw new HttpError(413, `${label} is too large`);
  const isDataUrl = /^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(v);
  const isUrl = /^https?:\/\/\S+$/.test(v);
  if (!isDataUrl && !isUrl) throw new HttpError(400, `${label} must be an uploaded image or a URL`);
  return v;
};

const sameEmail = (a, b) =>
  typeof a === "string" && typeof b === "string" && a.trim().toLowerCase() === b.trim().toLowerCase();

const escapeRegex = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// "YYYY-MM-DD HH:mm:ss" in Bangladesh time, matching the format the client always used
const stamp = (date = new Date()) =>
  new Intl.DateTimeFormat("sv-SE", {
    timeZone: "Asia/Dhaka",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);

module.exports = {
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
};
