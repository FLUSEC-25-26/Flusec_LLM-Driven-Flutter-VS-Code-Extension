// // src/ui/flusecNavigation.ts

// import * as vscode from "vscode";

// type ComponentId = "ivd";

// class FlusecNavItem extends vscode.TreeItem {
//   constructor(
//     label: string,
//     collapsibleState: vscode.TreeItemCollapsibleState,
//     options: {
//       nodeType: "component" | "action";
//       componentId?: ComponentId;
//       description?: string;
//       tooltip?: string;
//       icon?: vscode.ThemeIcon;
//       command?: vscode.Command;
//       contextValue?: string;
//     } = { nodeType: "component" }
//   ) {
//     super(label, collapsibleState);

//     this.contextValue = options.contextValue ?? options.nodeType;
//     this.description = options.description;
//     this.tooltip = options.tooltip;
//     this.iconPath = options.icon;
//     if (options.command) {
//       this.command = options.command;
//     }

//     if (options.componentId) {
//       this.id = `${options.nodeType}:${options.componentId}:${label}`;
//     }
//   }
// }

// class FlusecNavigationProvider
//   implements vscode.TreeDataProvider<FlusecNavItem>
// {
//   private _onDidChangeTreeData = new vscode.EventEmitter<
//     FlusecNavItem | undefined | null | void
//   >();
//   readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

//   private components: {
//     id: ComponentId;
//     label: string;
//     icon: vscode.ThemeIcon;
//   }[] = [
//     {
//       id: "ivd",
//       label: "Input Validation (IVD)",
//       icon: new vscode.ThemeIcon("checklist"),
//     },
//   ];

//   getTreeItem(element: FlusecNavItem): vscode.TreeItem {
//     return element;
//   }

//   getChildren(element?: FlusecNavItem): Thenable<FlusecNavItem[]> {
//     if (!element) {
//       const items = this.components.map(
//         (c) =>
//           new FlusecNavItem(
//             c.label,
//             vscode.TreeItemCollapsibleState.Collapsed,
//             {
//               nodeType: "component",
//               componentId: c.id,
//               tooltip: `Manage ${c.label}`,
//               icon: c.icon,
//               contextValue: `component-${c.id}`,
//             }
//           )
//       );
//       return Promise.resolve(items);
//     }

//     if (element.contextValue?.startsWith("component")) {
//       const componentId = this.extractComponentId(element);
//       if (componentId) {
//         return Promise.resolve(this.getActionsForComponent(componentId));
//       }
//     }

//     return Promise.resolve([]);
//   }

//   private extractComponentId(element: FlusecNavItem): ComponentId | null {
//     // ESLint Fix: Added braces to satisfy the 'curly' rule
//     if (!element.id) { 
//       return null; 
//     }
    
//     const parts = element.id.split(":");
//     if (parts.length < 2) { 
//       return null; 
//     }
    
//     const candidate = parts[1];
//     if (candidate === "ivd") {
//       return candidate as ComponentId;
//     }
    
//     return null;
//   }

//   private getActionsForComponent(componentId: ComponentId): FlusecNavItem[] {
//     switch (componentId) {
//       case "ivd": {
//         return [
//           new FlusecNavItem(
//             "IVD Dashboard",
//             vscode.TreeItemCollapsibleState.None,
//             {
//               nodeType: "action",
//               componentId,
//               tooltip: "View Input Validation Findings",
//               icon: new vscode.ThemeIcon("dashboard"),
//               command: {
//                 command: "flusec.openIvdFindings",
//                 title: "Open IVD Dashboard",
//               },
//             }
//           ),
//           new FlusecNavItem(
//             "IVD Rule Manager",
//             vscode.TreeItemCollapsibleState.None,
//             {
//               nodeType: "action",
//               componentId,
//               tooltip: "Manage Dynamic IVD Rules",
//               icon: new vscode.ThemeIcon("settings-gear"),
//               command: {
//                 command: "flusec.manageIvdRules",
//                 title: "Open IVD Rule Manager",
//               },
//             }
//           ),
//         ];
//       }
//     }
//     return [];
//   }

//   refresh(): void {
//     this._onDidChangeTreeData.fire();
//   }
// }

// export function registerFlusecNavigationView(
//   context: vscode.ExtensionContext
// ) {
//   const provider = new FlusecNavigationProvider();
//   vscode.window.createTreeView("flusecNavView", {
//     treeDataProvider: provider,
//     showCollapseAll: false,
//   });
// }





// src/ui/flusecNavigation.ts

import * as vscode from "vscode";

// 1. Expanded the type to include "arc"
type ComponentId = "ivd" | "arc";

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

  // 2. Added the Architecture (ARC) component to the main list
  private components: {
    id: ComponentId;
    label: string;
    icon: vscode.ThemeIcon;
  }[] = [
    {
      id: "ivd",
      label: "Input Validation (IVD)",
      icon: new vscode.ThemeIcon("shield"),
    },
    {
      id: "arc",
      label: "Architecture Insights (ARC)",
      icon: new vscode.ThemeIcon("symbol-class"),
    },
  ];

  getTreeItem(element: FlusecNavItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FlusecNavItem): Thenable<FlusecNavItem[]> {
    if (!element) {
      const items = this.components.map(
        (c) =>
          new FlusecNavItem(
            c.label,
            vscode.TreeItemCollapsibleState.Collapsed,
            {
              nodeType: "component",
              componentId: c.id,
              tooltip: `Manage ${c.label}`,
              icon: c.icon,
              contextValue: `component-${c.id}`,
            }
          )
      );
      return Promise.resolve(items);
    }

    if (element.contextValue?.startsWith("component")) {
      const componentId = this.extractComponentId(element);
      if (componentId) {
        return Promise.resolve(this.getActionsForComponent(componentId));
      }
    }

    return Promise.resolve([]);
  }

  private extractComponentId(element: FlusecNavItem): ComponentId | null {
    if (!element.id) { 
      return null; 
    }
    
    const parts = element.id.split(":");
    if (parts.length < 2) { 
      return null; 
    }
    
    const candidate = parts[1];
    // 3. Allow "arc" to be successfully extracted
    if (candidate === "ivd" || candidate === "arc") {
      return candidate as ComponentId;
    }
    
    return null;
  }

  private getActionsForComponent(componentId: ComponentId): FlusecNavItem[] {
    switch (componentId) {
      case "ivd": {
        return [
          new FlusecNavItem(
            "IVD Dashboard",
            vscode.TreeItemCollapsibleState.None,
            {
              nodeType: "action",
              componentId,
              tooltip: "View Input Validation Findings",
              icon: new vscode.ThemeIcon("dashboard"),
              command: {
                command: "flusec.openIvdFindings",
                title: "Open IVD Dashboard",
              },
            }
          ),
          new FlusecNavItem(
            "IVD Rule Manager",
            vscode.TreeItemCollapsibleState.None,
            {
              nodeType: "action",
              componentId,
              tooltip: "Manage Dynamic IVD Rules",
              icon: new vscode.ThemeIcon("settings-gear"),
              command: {
                command: "flusec.manageIvdRules",
                title: "Open IVD Rule Manager",
              },
            }
          ),
        ];
      }
      // 4. Added the action buttons for the ARC component
      case "arc": {
        return [
          new FlusecNavItem(
            "Cohesion Dashboard",
            vscode.TreeItemCollapsibleState.None,
            {
              nodeType: "action",
              componentId,
              tooltip: "View Class Cohesion & Architecture Metrics",
              icon: new vscode.ThemeIcon("graph-scatter"),
              command: {
                command: "flusec.openArcDashboard",
                title: "Open Cohesion Dashboard",
              },
            }
          ),
        ];
      }
    }
    return [];
  }

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }
}

export function registerFlusecNavigationView(
  context: vscode.ExtensionContext
) {
  const provider = new FlusecNavigationProvider();
  vscode.window.createTreeView("flusecNavView", {
    treeDataProvider: provider,
    showCollapseAll: false,
  });
}