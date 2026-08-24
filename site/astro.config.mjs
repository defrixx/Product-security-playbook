import { defineConfig } from 'astro/config';
import { unified } from '@astrojs/markdown-remark';
import starlight from '@astrojs/starlight';
import rehypeMermaid from './plugins/rehype-mermaid.mjs';
import mermaidIntegration from './plugins/mermaid-integration.mjs';

const repository = process.env.GITHUB_REPOSITORY ?? '';
const configuredBase =
  process.env.PUBLIC_SITE_BASE ??
  (repository.endsWith('/defrixx.github.io') ? '' : '/Product-security-playbook');

export default defineConfig({
  site: 'https://defrixx.github.io',
  ...(configuredBase ? { base: configuredBase } : {}),
  markdown: {
    processor: unified({ rehypePlugins: [rehypeMermaid] }),
  },
  integrations: [
    mermaidIntegration(),
    starlight({
      disable404Route: true,
      title: 'Product Security Playbook',
      description:
        'Practical product security playbooks for architecture review, AppSec, platform security, supply chain, and AI security.',
      defaultLocale: 'en',
      locales: {
        ru: {
          label: 'Русский',
          lang: 'ru',
        },
        en: {
          label: 'English',
          lang: 'en',
        },
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/defrixx/Product-security-playbook',
        },
      ],
      customCss: ['./src/styles/custom.css'],
      sidebar: [
        {
          label: 'Ревью и управление',
          translations: { en: 'Review and Governance' },
          items: [
            { slug: 'review/architecture/checklist' },
            { slug: 'review/threat-modeling/playbook' },
            { slug: 'review/release-governance/playbook' },
            { slug: 'review/vulnerability-management/playbook' },
          ],
        },
        {
          label: 'Application Security',
          items: [
            {
              label: 'Web',
              items: [
                { slug: 'application-security/web/owasp-top-10/playbook' },
                { slug: 'application-security/web/browser-security/playbook' },
              ],
            },
            { slug: 'application-security/api/api-security-patterns/playbook' },
            { slug: 'application-security/business-logic/business-logic-abuse/playbook' },
            { slug: 'application-security/secure-coding/code-review/playbook' },
            { slug: 'application-security/identity/oidc-oauth/playbook' },
          ],
        },
        {
          label: 'Platform Security',
          items: [
            {
              label: 'Kubernetes',
              items: [
                { slug: 'platform-security/kubernetes/cluster-security-review/playbook' },
                { slug: 'platform-security/kubernetes/adversarial-validation/playbook' },
                { slug: 'platform-security/kubernetes/pod-security/playbook' },
                { slug: 'platform-security/kubernetes/secrets/playbook' },
                { slug: 'platform-security/kubernetes/seccomp/checklist' },
                { slug: 'platform-security/kubernetes/container-escape-capability-abuse/overview' },
              ],
            },
            { slug: 'platform-security/secrets/vault/playbook' },
          ],
        },
        {
          label: 'Supply Chain',
          items: [
            { slug: 'supply-chain/slsa-provenance/overview' },
            { slug: 'supply-chain/container-image-security/playbook' },
          ],
        },
        {
          label: 'AI Security',
          items: [
            { slug: 'ai-security/securing-ai/overview' },
            { slug: 'ai-security/owasp-llm-top-10/overview' },
            { slug: 'ai-security/agentic-ai/playbook' },
            { slug: 'ai-security/ai-assisted-development/playbook' },
            { slug: 'ai-security/mcp-security/playbook' },
          ],
        },
        {
          label: 'Справочник',
          translations: { en: 'Reference' },
          items: [{ slug: 'reference/infrastructure-technologies/infrastructure-technologies' }],
        },
      ],
    }),
  ],
});
