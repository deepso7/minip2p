# @minip2p/core

Platform-neutral types and SDK behavior for minip2p.

Applications normally install a platform package such as `react-native-minip2p` or `@minip2p/node`; those packages bind the SDK to a native backend and re-export the public core types.

Adapter authors implement the deliberately small contract exported from `@minip2p/core/backend`. The core package never imports React Native, Node.js, UniFFI, napi-rs, or generated native code.
