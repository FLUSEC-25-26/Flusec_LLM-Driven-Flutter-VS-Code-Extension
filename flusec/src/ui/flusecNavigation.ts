// src/ui/flusecNavigation.ts
//
// FLUSEC Navigation Sidebar (TreeView) – HSD only
//
// This ONLY acts as a navigation menu.
// It does NOT implement dashboards or rule managers itself.
// It simply calls existing commands:
//
//   HSD (your component):
//     - flusec.openFindings       → HSD dashboard (src/web/hsd/dashboard.html)
//     - flusec.manageRules        → HSD rule manager
//
// Future components (commented out for now):
//   - Network Security
//   - Secure Storage
//   - Input Validation
//
// When you want them later, you can uncomment the relevant sections.

import * as vscode from "vscode";

type ComponentId = "hsd" /* | "network" | "storage" | "inputValidation" */;

class FlusecNavItem extends vscode.TreeItem {
  constructor(
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    options: {
      nodeType: "component" | "action";
      componentId?: ComponentId;
      description?: string;
      tooltip?: string;
      icon?: vscode.ThemeIcon;
      command?: vscode.Command;
      contextValue?: string;
    } = { nodeType: "component" }
  ) {
    super(label, collapsibleState);

    this.contextValue = options.contextValue ?? options.nodeType;
    this.description = options.description;
    this.tooltip = options.tooltip;
    this.iconPath = options.icon;
    if (options.command) {
      this.command = options.command;
    }

    // Store componentId inside id – useful if you expand later
    if (options.componentId) {
      this.id = `${options.nodeType}:${options.componentId}:${label}`;
    }
  }
}

class FlusecNavigationProvider
  implements vscode.TreeDataProvider<FlusecNavItem>
{
  private _onDidChangeTreeData = new vscode.EventEmitter<
    FlusecNavItem | undefined | null | void
  >();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  //  Only HSD for now (your component)
  private components: {
    id: ComponentId;
    label: string;
    icon: vscode.ThemeIcon;
  }[] = [
    {
      id: "hsd",
      label: "Hardcoded Secrets (HSD)",
      icon: new vscode.ThemeIcon("shield"),
    },

    // Uncomment later when you add other components

    // {
    //   id: "network",
    //   label: " Network Security",
    //   description: "Future component",
    //   icon: new vscode.ThemeIcon("rss"),
    // },
    // {
    //   id: "storage",
    //   label: " Secure Storage",
    //   description: "Future component",
    //   icon: new vscode.ThemeIcon("database"),
    // },
    // {
    //   id: "inputValidation",
    //   label: "Input Validation",
    //   description: "Future component",
    //   icon: new vscode.ThemeIcon("checklist"),
    // },
  ];

  getTreeItem(element: FlusecNavItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FlusecNavItem): Thenable<FlusecNavItem[]> {
    // Root level → show components (currently only HSD)
    if (!element) {
      const items = this.components.map(
        (c) =>
          new FlusecNavItem(
            c.label,
            vscode.TreeItemCollapsibleState.Collapsed,
            {
              nodeType: "component",
              componentId: c.id,
              tooltip: "Your module: Hardcoded Secrets Detection (HSD)",
              icon: c.icon,
              contextValue: "component-hsd",
            }
          )
      );
      return Promise.resolve(items);
    }

    // Children for a component node
    if (element.contextValue?.startsWith("component")) {
      const componentId = this.extractComponentId(element);
      if (componentId) {
        return Promise.resolve(this.getActionsForComponent(componentId));
      }
    }

    // Action nodes have no children
    return Promise.resolve([]);
  }

  private extractComponentId(element: FlusecNavItem): ComponentId | null {
    if (!element.id) {return null;}
    const parts = element.id.split(":");
    if (parts.length < 2) {return null;}
    const candidate = parts[1] as ComponentId;
    if (candidate === "hsd") {
      return candidate;
    }
    // Later, if you re-add others, extend this check.
    return null;
  }

  private getActionsForComponent(componentId: ComponentId): FlusecNavItem[] {
    switch (componentId) {
      //
      //  component: HSD
      //
      case "hsd": {
        const dashboard = new FlusecNavItem(
          "HSD Dashboard",
          vscode.TreeItemCollapsibleState.None,
          {
            nodeType: "action",
            componentId,
            
            tooltip:
              "Open the Hardcoded Secrets (HSD) dashboard – shows findings for your component.",
            icon: new vscode.ThemeIcon("graph"),
            command: {
              command: "flusec.openFindings",
              title: "Open HSD Dashboard",
            },
            contextValue: "hsd-dashboard",
          }
        );

        const ruleManager = new FlusecNavItem(
          "HSD Rule Manager",
          vscode.TreeItemCollapsibleState.None,
          {
            nodeType: "action",
            componentId,
            
            tooltip:
              "Open the HSD Rule Manager – add, edit, or delete dynamic rules for hardcoded secrets.",
            icon: new vscode.ThemeIcon("wrench"),
            command: {
              command: "flusec.manageRules",
              title: "Open HSD Rule Manager",
            },
            contextValue: "hsd-rule-manager",
          }
        );

        return [dashboard, ruleManager];
      }

      // Future components can be re-added here later
      // case "network": { ... }
      // case "storage": { ... }
      // case "inputValidation": { ... }
    }
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }
}

/**
 * Register the FLUSEC navigation tree view.
 * This is called once in extension.activate().
 */
export function registerFlusecNavigationView(
  context: vscode.ExtensionContext
) {
  const provider = new FlusecNavigationProvider();
  const treeView = vscode.window.createTreeView("flusecNavView", {
    treeDataProvider: provider,
    showCollapseAll: false,
  });

  context.subscriptions.push(treeView);
}
