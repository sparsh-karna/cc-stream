document$.subscribe(() => {
  document.querySelectorAll("pre.mermaid").forEach((block) => {
    const code = block.querySelector("code");
    if (!code || block.dataset.mermaidConverted === "true") {
      return;
    }

    const graph = code.textContent || "";
    const container = document.createElement("div");
    container.className = "mermaid";
    container.textContent = graph;

    block.dataset.mermaidConverted = "true";
    block.replaceWith(container);
  });

  if (typeof mermaid === "undefined") {
    return;
  }

  mermaid.initialize({
    startOnLoad: false,
  });
  mermaid.run({ querySelector: ".mermaid:not([data-processed])" });
});
