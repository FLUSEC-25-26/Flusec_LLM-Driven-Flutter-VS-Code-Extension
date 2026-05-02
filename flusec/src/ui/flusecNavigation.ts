import * as vscode from "vscode";

interface NavItem {
  label: string;
  command?: string;
  icon?: string;
  children?: NavItem[];
}

const NAV_ITEMS: NavItem[] = [
  {
    label: "Scan Entire Project",
    command: "flusec.scanProject",
    icon: "play-circle",
  },
  {
    label: "Dashboards",
    icon: "graph",
    children: [
      {
        label: "Hardcoded Secrets (HSD)",
        command: "flusec.openFindings",
        icon: "key",
      },
      {
        label: "Network Security (NET)",
        command: "flusec.openNetDashboard",
        icon: "globe",
      },
      {
        label: "Data Storage (IDS)",
        command: "flusec.openIDSDashboard",
        icon: "database",
      },
      {
        label: "Input Validation (IIV)",
        command: "flusec.openIIVDashboard",
        icon: "shield",
      },
    ],
  },
  {
    label: "Policies",
    icon: "checklist",
    children: [
      {
        label: "Sync Policies",
        command: "flusec.updateRulePacks",
        icon: "sync",
      },
    ],
  },
  {
    label: "Team Collaboration",
    icon: "organization",
    children: [
      {
        label: "Login to Team",
        command: "flusec.loginToTeam",
        icon: "sign-in",
      },
      {
        label: "Sync Findings",
        command: "flusec.uploadFindings",
        icon: "cloud-upload",
      },
      {
        label: "Logout",
        command: "flusec.logoutFromTeam",
        icon: "sign-out",
      },
    ],
  },
];

class FlusecNavItem extends vscode.TreeItem {
  constructor(public readonly nav: NavItem) {
    super(
      nav.label,
      nav.children
        ? vscode.TreeItemCollapsibleState.Expanded
        : vscode.TreeItemCollapsibleState.None
    );

    this.tooltip = nav.label;

    if (nav.command) {
      this.command = {
        command: nav.command,
        title: nav.label,
      };
    }

    if (nav.icon) {
      this.iconPath = new vscode.ThemeIcon(nav.icon);
    }

    this.contextValue = nav.children ? "category" : "action";
  }
}

class FlusecNavigationProvider
  implements vscode.TreeDataProvider<FlusecNavItem>
{
  private _onDidChangeTreeData = new vscode.EventEmitter<
    FlusecNavItem | undefined | null | void
  >();

  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: FlusecNavItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: FlusecNavItem): Thenable<FlusecNavItem[]> {
    if (element) {
      const children = element.nav.children || [];
      return Promise.resolve(children.map((item) => new FlusecNavItem(item)));
    }

    return Promise.resolve(NAV_ITEMS.map((item) => new FlusecNavItem(item)));
  }
}

export function registerFlusecNavigationView(
  context: vscode.ExtensionContext
): void {
  const provider = new FlusecNavigationProvider();

  const treeView = vscode.window.createTreeView("flusecNavView", {
    treeDataProvider: provider,
    showCollapseAll: true,
  });

  context.subscriptions.push(treeView);
}