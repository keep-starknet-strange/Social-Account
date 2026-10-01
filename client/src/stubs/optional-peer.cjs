// Stand-in for starkzap optional peers (ethers, tongo) that this app never uses.
// CommonJS on purpose: any named import from it resolves to undefined instead of failing the build.
module.exports = {};
