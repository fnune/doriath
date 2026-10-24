// Page parts that make noise in Markdown: heading anchor links, and the
// parts of components that only decorate.
export const markdownStrip = [".sl-anchor-link", "[data-no-markdown]"];

export function markdownHref(id) {
  if (id === "404") return undefined;
  return `/${id || "index"}.md`;
}
