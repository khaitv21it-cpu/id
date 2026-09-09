const { Redis } = require("@upstash/redis");

let client = null;

function getRedis() {
  if (client) return client;
  const url =
    process.env.UPSTASH_REDIS_REST_URL ||
    process.env.KV_REST_API_URL ||
    process.env.REDIS_URL;
  const token =
    process.env.UPSTASH_REDIS_REST_TOKEN ||
    process.env.KV_REST_API_TOKEN ||
    process.env.REDIS_TOKEN;
  if (!url || !token) return null;
  client = new Redis({ url, token });
  return client;
}

function isStoreConfigured() {
  return Boolean(getRedis());
}

module.exports = { getRedis, isStoreConfigured };
