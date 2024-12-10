import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */
const sidebars: SidebarsConfig = {
  // But you can create a sidebar manually
  docsSidebar: [
    {
      type: "category",
      label: "Getting Started",
      items: [
        {
          type: "doc",
          label: "Introduction",
          id: "getting-started/introduction",
        },
        {
          type: "doc",
          label: "Quick Start",
          id: "getting-started/quick-start",
        },
        { type: "doc", label: "Glossary", id: "getting-started/glossary" },
      ],
    },
    {
      type: "category",
      label: "CLI",
      items: [
        {
          type: "doc",
          label: "Installation",
          id: "cli/install",
        },
        {
          type: "category",
          label: "Commands",
          link: { type: "doc", id: "cli/command/index" },
          items: [
            {
              type: "doc",
              label: "Config",
              id: "cli/command/config",
            },
            {
              type: "doc",
              label: "Login",
              id: "cli/command/login",
            },
            {
              type: "doc",
              label: "Authority",
              id: "cli/command/authority",
            },
            {
              type: "doc",
              label: "Path",
              id: "cli/command/path",
            },
            {
              type: "doc",
              label: "Access Condition",
              id: "cli/command/access-condition",
            },
            {
              type: "doc",
              label: "Secret",
              id: "cli/command/secret",
            },
          ],
        },
      ],
    },

    {
      type: "category",
      label: "Configurations",
      items: [
        {
          type: "doc",
          label: "Backbone server",
          id: "config/backbone",
        },
        {
          type: "doc",
          label: "Authorization server",
          id: "config/authorization",
        },
        {
          type: "doc",
          label: "Authority server",
          id: "config/authority",
        },
      ],
    },
  ],
};

export default sidebars;
