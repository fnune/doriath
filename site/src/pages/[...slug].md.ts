// The HTML to Markdown steps follow entryToSimpleMarkdown.ts of
// starlight-llms-txt (MIT, Chris Swithinbank), which does not export them.
import mdxServer from "@astrojs/mdx/server.js";
import type { APIRoute, GetStaticPaths } from "astro";
import { experimental_AstroContainer } from "astro/container";
import { getCollection, render, type CollectionEntry } from "astro:content";
import type { Element, Root } from "hast";
import { matches, select, selectAll } from "hast-util-select";
import rehypeParse from "rehype-parse";
import rehypeRemark from "rehype-remark";
import remarkGfm from "remark-gfm";
import remarkStringify from "remark-stringify";
import { unified } from "unified";
import { markdownStrip } from "../markdown.mjs";

export const prerender = true;

type Props = { entry: CollectionEntry<"docs"> };

export const getStaticPaths = (async () => {
  const docs = await getCollection("docs", (entry) => entry.id !== "404");
  return docs.map((entry) => ({ params: { slug: entry.id }, props: { entry } }));
}) satisfies GetStaticPaths;

const container = await experimental_AstroContainer.create({
  renderers: [{ name: "astro:jsx", ssr: mdxServer }],
});

const toMarkdown = unified()
  .use(rehypeParse, { fragment: true })
  .use(() => (tree: Root) => {
    strip(tree);
    for (const link of selectAll("a[href^='/']", tree)) {
      link.properties.href = markdownPath(String(link.properties.href));
    }
    for (const block of selectAll(".expressive-code", tree)) {
      const pre = select("pre", block);
      const code = select("code", block);
      if (pre?.properties.dataLanguage && code) {
        code.properties.className = [`language-${pre.properties.dataLanguage}`];
      }
      const label = select("figcaption .sr-only", block);
      if (label) label.children = [];
    }
    for (const tabs of selectAll("starlight-tabs", tree)) {
      const labels = selectAll('[role="tab"]', tabs);
      const panels = selectAll('[role="tabpanel"]', tabs);
      tabs.tagName = "ul";
      tabs.properties = {};
      tabs.children = panels.map((panel, i) => ({
        type: "element",
        tagName: "li",
        properties: {},
        children: [
          {
            type: "element",
            tagName: "p",
            properties: {},
            children: [{ type: "text", value: textOf(labels[i]) }],
          },
          panel,
        ],
      }));
    }
  })
  .use(rehypeRemark)
  .use(remarkGfm)
  .use(remarkStringify);

function strip(node: Root | Element) {
  node.children = node.children.filter(
    (child) => child.type !== "element" || !markdownStrip.some((selector) => matches(selector, child)),
  );
  for (const child of node.children) {
    if (child.type === "element") strip(child);
  }
}

function markdownPath(href: string): string {
  const [path, hash] = href.split("#");
  const page = path === "/" ? "/index" : path.replace(/\/$/, "");
  return `${page}.md${hash ? `#${hash}` : ""}`;
}

function textOf(node: ReturnType<typeof select>): string {
  if (!node) return "";
  return node.children
    .map((child) => (child.type === "text" ? child.value : child.type === "element" ? textOf(child) : ""))
    .join("")
    .trim();
}

export const GET: APIRoute<Props> = async (context) => {
  const { entry } = context.props;
  const { Content } = await render(entry);
  const html = await container.renderToString(Content, context);
  const body = String(await toMarkdown.process(html)).trim();
  const head = [`# ${entry.data.title}`, entry.data.description && `> ${entry.data.description}`].filter(Boolean);
  return new Response([...head, body].join("\n\n") + "\n", {
    headers: { "Content-Type": "text/markdown; charset=utf-8" },
  });
};
