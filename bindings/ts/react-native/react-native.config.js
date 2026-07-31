/**
 * @type {import('@react-native-community/cli-types').UserDependencyConfig}
 */
/* oxlint-disable unicorn/prefer-module -- The React Native CLI loads this package config through CommonJS. */

module.exports = {
  dependency: {
    platforms: {
      android: {
        cmakeListsPath: "generated/jni/CMakeLists.txt",
      },
    },
  },
};
