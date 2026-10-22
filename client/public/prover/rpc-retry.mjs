// Retry transient HTTP failures only for reads. Never replay a transaction broadcast.
export async function fetchRpc(
  url,
  options,
  {
    fetchImpl = fetch,
    sleep = (ms) => new Promise((r) => setTimeout(r, ms)),
  } = {},
) {
  let method;
  try {
    method = JSON.parse(options.body).method;
  } catch {}
  const read =
    typeof method === "string" &&
    (/^(starknet_get|starknet_trace)/.test(method) ||
      [
        "starknet_call",
        "starknet_chainId",
        "starknet_specVersion",
        "starknet_blockNumber",
      ].includes(method));
  for (let attempt = 0; ; attempt++) {
    options.signal?.throwIfAborted();
    const response = await fetchImpl(url, options);
    if (
      !read ||
      attempt === 4 ||
      ![429, 502, 503, 504].includes(response.status)
    )
      return response;
    const retryAfter = Number(response.headers?.get("retry-after"));
    const delay =
      Number.isFinite(retryAfter) && retryAfter > 0
        ? Math.min(retryAfter * 1000, 20000)
        : 1000 * 2 ** attempt;
    await response.body?.cancel();
    await sleep(delay);
  }
}
