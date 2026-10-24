import { defineRouteMiddleware } from "@astrojs/starlight/route-data";
import { markdownHref } from "./markdown.mjs";

export const onRequest = defineRouteMiddleware((context) => {
  const route = context.locals.starlightRoute;
  const href = markdownHref(route.entry.id);
  if (href) route.head.push({ tag: "link", attrs: { rel: "alternate", type: "text/markdown", href } });
});
