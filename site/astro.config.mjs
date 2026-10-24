import { defineConfig, passthroughImageService } from "astro/config";
import starlight from "@astrojs/starlight";

export default defineConfig({
  site: "https://doriath.fnune.com",
  redirects: {
    "/forges/github": "/forges/#github",
    "/forges/gitlab": "/forges/#gitlab",
    "/forges/forgejo": "/forges/#forgejo-gitea-and-codeberg",
    "/forges/bitbucket": "/forges/#bitbucket",
  },
  image: {
    service: passthroughImageService(),
  },
  vite: {
    server: { fs: { allow: [".."] } },
    build: { assetsInlineLimit: 0 },
  },
  integrations: [
    starlight({
      title: "Doriath",
      description: "Run coding agents in a jail that shows them only what their task needs.",
      favicon: "/favicon.svg",
      components: {
        SiteTitle: "./src/components/SiteTitle.astro",
      },
      customCss: ["../internal/ui/tokens.css", "../internal/ui/components.css", "./src/styles/custom.css"],
      expressiveCode: {
        themes: ["github-dark", "github-light"],
        defaultProps: { wrap: true },
        styleOverrides: {
          borderRadius: "3px",
          borderColor: "var(--line)",
          codeBackground: "var(--code)",
          codeFontFamily: "var(--font-mono)",
          uiFontFamily: "var(--font-body)",
          frames: {
            editorBackground: "var(--code)",
            editorTabBarBackground: "var(--surface)",
            editorActiveTabBackground: "var(--code)",
            editorActiveTabIndicatorTopColor: "var(--ring)",
            terminalBackground: "var(--code)",
            terminalTitlebarBackground: "var(--surface)",
            terminalTitlebarBorderBottomColor: "var(--line)",
            frameBoxShadowCssValue: "none",
          },
        },
      },
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/fnune/doriath",
        },
      ],
      sidebar: [
        { label: "Install", slug: "install" },
        {
          label: "Concepts",
          items: [
            { label: "Architecture", slug: "architecture" },
            { label: "Threat model", slug: "threat-model" },
          ],
        },
        {
          label: "Guides",
          items: [
            { label: "Profiles with an agent", slug: "guides/profile-setup" },
            { label: "Answering requests", slug: "guides/approvals" },
            { label: "home-manager", slug: "guides/home-manager" },
            { label: "Projects with direnv", slug: "guides/direnv" },
            { label: "Cloud credentials", slug: "guides/cloud" },
            { label: "Looking inside a session", slug: "guides/inside-a-session" },
          ],
        },
        { label: "Forges", slug: "forges" },
        {
          label: "Agents",
          items: [
            { label: "Overview", slug: "agents" },
            { label: "Claude Code", slug: "agents/claude-code" },
            { label: "Codex", slug: "agents/codex" },
            { label: "Gemini CLI", slug: "agents/gemini-cli" },
            { label: "opencode", slug: "agents/opencode" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "Configuration", slug: "reference/configuration" },
            { label: "Modules", slug: "reference/modules" },
            { label: "Commands", slug: "reference/commands" },
          ],
        },
        { label: "Development", slug: "development" },
      ],
    }),
  ],
});
