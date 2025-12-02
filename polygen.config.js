module.exports = {
  outputDir: "wasm",           // where generated glue code goes
  targets: ["react-native"],   // target platform
  scan: {
    paths: ["wasm/qrs.wasm"]  // your compiled WASM file
  },
  modules: [
    {
      kind: "local",          // local WASM module
      path: "wasm/qrs.wasm",  // path relative to repo root
      name: "qrs"             // optional: internal name
    }
  ]
};
