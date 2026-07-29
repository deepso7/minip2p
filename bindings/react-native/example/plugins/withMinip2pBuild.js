const { withProjectBuildGradle } = require('expo/config-plugins');

const NDK_VERSION = '28.2.13676358';
const MARKER = '// minip2p: Android toolchain';

module.exports = function withMinip2pBuild(config) {
  return withProjectBuildGradle(config, (project) => {
    if (project.modResults.language !== 'groovy') {
      throw new Error('minip2p requires a Groovy Android project build file');
    }

    const block = `${MARKER}
ext {
  ndkVersion = "${NDK_VERSION}"
}
`;
    const withoutPreviousBlock = project.modResults.contents.replace(
      new RegExp(`${escapeRegExp(MARKER)}[\\s\\S]*?\\n}\\n`, 'm'),
      ''
    );
    project.modResults.contents = `${block}\n${withoutPreviousBlock}`;
    return project;
  });
};

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
