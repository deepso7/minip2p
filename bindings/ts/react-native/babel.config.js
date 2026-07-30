/* oxlint-disable unicorn/prefer-module -- Babel loads this configuration through CommonJS. */

module.exports = {
  overrides: [
    {
      exclude: /\/node_modules\//u,
      presets: ["module:react-native-builder-bob/babel-preset"],
    },
    {
      include: /\/node_modules\//u,
      presets: ["module:@react-native/babel-preset"],
    },
  ],
};
