// Shared facts about the layout shell (site-header, breadcrumbs).

/**
 * Whether `route` is the one RootLayout page without a sidebar: the changelog
 * index Blume generates with `contentLayout: "bare"`. Its header is a plain
 * top row that carries the section tabs, instead of the block pinned above
 * the sidebar.
 */
export const isBareRoute = (route: string) => route === "/changelog";
