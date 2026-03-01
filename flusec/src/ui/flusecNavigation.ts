// src/ui/flusecNavigation.ts
//
// FLUSEC Navigation Sidebar (TreeView)
// Active: HSD + Network + Storage (IDS)
// Top-level: Scan Entire Project (scans all components)
// Future: Input Validation (commented out)

import * as vscode from "vscode";

type ComponentId = "hsd" | "network" | "storage" /* | "inputValidation" */;

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

  // Active components
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
    {
      id: "network",
      label: "Network Security (NET)",
      icon: new vscode.ThemeIcon("rss"),
    },
    {
      id: "storage",
      label: "Secure Storage (IDS)",
      icon: new vscode.ThemeIcon("database"),
    },

    // Uncomment when ready:
    // {
    //   id: "inputValidation",
    //   label: "Input Validation (IIV)",
    //   icon: new vscode.ThemeIcon("checklist"),
    // },
  ];

  getTreeItem(element: FlusecNavItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FlusecNavItem): Thenable<FlusecNavItem[]> {
    // Root level → show project scan button + components
    if (!element) {
      // Top-level "Scan Entire Project" button (scans ALL components)
      const projectScan = new FlusecNavItem(
        "Scan Entire Project",
        vscode.TreeItemCollapsibleState.None,
        {
          nodeType: "action",
          tooltip: "Scan all Dart files for all vulnerability types (HSD, NET, IDS).",
          icon: new vscode.ThemeIcon("search"),
          command: {
            command: "flusec.scanProject",
            title: "Scan Entire Project",
          },
          contextValue: "project-scan",
        }
      );

      // Component items (collapsible)
      const items = this.components.map(
        (c) =>
          new FlusecNavItem(
            c.label,
            vscode.TreeItemCollapsibleState.Collapsed,
            {
              nodeType: "component",
              componentId: c.id,
              tooltip: `FLUSEC component: ${c.label}`,
              icon: c.icon,
              contextValue: `component-${c.id}`,
            }
          )
      );

      return Promise.resolve([projectScan, ...items]);
    }

    // Children for a component node
    if (element.contextValue?.startsWith("component")) {
      const componentId = this.extractComponentId(element);
      if (componentId) {
        return Promise.resolve(this.getActionsForComponent(componentId));
      }
    }

    return Promise.resolve([]);
  }

  private extractComponentId(element: FlusecNavItem): ComponentId | null {
    if (!element.id) {return null;}
    const parts = element.id.split(":");
    if (parts.length < 2) {return null;}
    const candidate = parts[1] as ComponentId;
    if (candidate === "hsd" || candidate === "network" || candidate === "storage") {
      return candidate;
    }
    return null;
  }

  private getActionsForComponent(componentId: ComponentId): FlusecNavItem[] {
    switch (componentId) {
      // ─── HSD ─────────────────────────────────────────────────────────
      case "hsd": {
        const dashboard = new FlusecNavItem(
          "HSD Dashboard",
          vscode.TreeItemCollapsibleState.None,
          {
            nodeType: "action",
            componentId,
            tooltip: "Open the Hardcoded Secrets dashboard – shows findings for HSD.",
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
            tooltip: "Add, edit, or delete dynamic rules for hardcoded secrets.",
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

      // ─── Network ────────────────────────────────────────────────────
      case "network": {
        const dashboard = new FlusecNavItem(
          "NET Dashboard",
          vscode.TreeItemCollapsibleState.None,
          {
            nodeType: "action",
            componentId,
            tooltip: "Open the Network Security dashboard – shows insecure network findings.",
            icon: new vscode.ThemeIcon("graph"),
            command: {
              command: "flusec.openNetDashboard",
              title: "Open NET Dashboard",
            },
            contextValue: "net-dashboard",
          }
        );

        return [dashboard];
      }

      // ─── Storage (IDS) ──────────────────────────────────────────────
      case "storage": {
        const dashboard = new FlusecNavItem(
          "IDS Dashboard",
          vscode.TreeItemCollapsibleState.None,
          {
            nodeType: "action",
            componentId,
            tooltip: "Open the Insecure Data Storage dashboard – shows storage vulnerability findings.",
            icon: new vscode.ThemeIcon("graph"),
            command: {
              command: "flusec.openIDSDashboard",
              title: "Open IDS Dashboard",
            },
            contextValue: "ids-dashboard",
          }
        );

        // IDS component has no user rule manager (base rules only from repo).
        // If you want one later, add it here same as HSD.

        return [dashboard];
      }

      // Future:
      // case "inputValidation": { ... }
    }

    return [];
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }
}

/**
 * Register the FLUSEC navigation tree view.
 * Called once in extension.activate().
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