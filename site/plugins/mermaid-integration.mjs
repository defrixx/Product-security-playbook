export default function mermaidIntegration() {
  return {
    name: 'product-security-playbook-mermaid',
    hooks: {
      'astro:config:setup': ({ injectScript }) => {
        injectScript(
          'page',
          `
          const diagramSources = new WeakMap();
          let mermaidPromise;
          let renderQueue = Promise.resolve();

          function loadMermaid() {
            mermaidPromise ??= import('mermaid').then(({ default: mermaid }) => mermaid);
            return mermaidPromise;
          }

          function currentTheme() {
            return document.documentElement.dataset.theme === 'dark' ? 'dark' : 'default';
          }

          async function renderMermaid() {
            const diagrams = Array.from(document.querySelectorAll('.mermaid'));
            if (diagrams.length === 0) return;

            const mermaid = await loadMermaid();

            for (const diagram of diagrams) {
              const source = diagramSources.get(diagram) ?? diagram.textContent ?? '';
              diagramSources.set(diagram, source);
              diagram.removeAttribute('data-processed');
              diagram.textContent = source;
            }

            mermaid.initialize({
              startOnLoad: false,
              securityLevel: 'strict',
              theme: currentTheme(),
            });

            await mermaid.run({ nodes: diagrams });
          }

          function scheduleRender() {
            renderQueue = renderQueue.then(renderMermaid).catch((error) => {
              console.error('Unable to render Mermaid diagrams.', error);
            });
          }

          scheduleRender();

          const observer = new MutationObserver(() => {
            scheduleRender();
          });

          observer.observe(document.documentElement, {
            attributes: true,
            attributeFilter: ['data-theme'],
          });
          `
        );
      },
    },
  };
}
