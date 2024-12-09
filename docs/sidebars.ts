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
        // {
        //   type: "category",
        //   label: "Commands",
        //   items: [],
        // },
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
