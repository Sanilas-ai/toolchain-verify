package reposcan

import (
	"path"
	"strings"
)

// Control-file kinds: files that an agent, editor or package manager loads
// as instructions or runs automatically.
const (
	KindInstructions = "instructions"  // AGENTS.md, CLAUDE.md, rules, skills, prompts
	KindMCP          = "mcp-config"    // .mcp.json, .cursor/mcp.json, ...
	KindAgentConfig  = "agent-config"  // .claude/settings*.json, .gemini/settings.json, hooks
	KindCodexConfig  = "codex-config"  // .codex/config.toml
	KindEditorTasks  = "editor-tasks"  // .vscode/tasks.json
	KindEditorConfig = "editor-config" // .vscode/settings.json
	KindWorkflow     = "ci-workflow"   // .github/workflows/*.yml, action.yml
	KindPackageHook  = "package-hook"  // package.json, extconf.rb, *.gemspec, setup.py, .pth
	KindSkillScript  = "skill-script"  // scripts shipped next to a SKILL.md
)

// classify returns the control kind of a slash-separated path relative to
// the scan root, or "". Matching is case-insensitive because macOS/Windows
// checkouts are, and several clients load names case-insensitively.
func classify(rel string) string {
	l := strings.ToLower(rel)
	base := path.Base(l)
	dir := path.Dir(l)
	parent := path.Base(dir)
	under := func(seg string) bool { return strings.HasPrefix(l, seg+"/") || strings.Contains(l, "/"+seg+"/") }

	switch base {
	case "agents.md", "agent.md", "claude.md", "claude.local.md", "gemini.md", ".cursorrules", ".windsurfrules",
		".clinerules", ".roorules", "copilot-instructions.md", "skill.md", "conventions.md", ".goosehints", "qwen.md", "crush.md":
		if base == "conventions.md" && dir != "." {
			return "" // aider only loads it when configured; root copy is enough
		}
		return KindInstructions
	case ".mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json", "mcp_settings.json", "cline_mcp_settings.json":
		return KindMCP
	case "hooks.json":
		if parent == ".cursor" || parent == ".claude" || parent == ".codex" {
			return KindAgentConfig
		}
	case "settings.json", "settings.local.json":
		switch parent {
		case ".claude", ".gemini", ".qwen":
			return KindAgentConfig
		case ".vscode", ".cursor", ".windsurf":
			return KindEditorConfig
		case ".zed":
			return KindMCP // context_servers
		}
	case "config.toml":
		if parent == ".codex" {
			return KindCodexConfig
		}
	case "tasks.json":
		if parent == ".vscode" || parent == ".cursor" || parent == ".windsurf" {
			return KindEditorTasks
		}
	case "package.json", "extconf.rb", "setup.py", "binding.gyp":
		if under("node_modules") {
			return ""
		}
		return KindPackageHook
	case "action.yml", "action.yaml":
		return KindWorkflow
	case ".aider.conf.yml":
		return KindAgentConfig
	}
	switch {
	case strings.HasSuffix(base, ".gemspec"), strings.HasSuffix(base, ".pth"):
		return KindPackageHook
	case (strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")) && strings.HasSuffix(dir, ".github/workflows"):
		return KindWorkflow
	case under(".cursor/rules"), under(".windsurf/rules"), under(".clinerules"), under(".roo/rules"),
		under(".kiro/steering"), under(".continue/rules"), under(".amazonq/rules"), under(".trae/rules"),
		under(".claude/commands"), under(".claude/agents"), under(".claude/skills"), under(".agents/skills"),
		under(".codex/prompts"), under(".gemini/commands"), under(".junie"), under(".augment/rules"):
		if isTextName(base) {
			return KindInstructions
		}
	case strings.HasSuffix(base, ".instructions.md") || strings.HasSuffix(base, ".prompt.md") || strings.HasSuffix(base, ".chatmode.md") || strings.HasSuffix(base, ".agent.md"):
		if under(".github") || under(".vscode") {
			return KindInstructions
		}
	case parent == ".roo" && strings.HasPrefix(base, "mcp"):
		return KindMCP
	case parent == ".amazonq" && base == "mcp.json":
		return KindMCP
	}
	return ""
}

func isTextName(base string) bool {
	for _, ext := range []string{".md", ".mdc", ".mdx", ".txt", ".json", ".yaml", ".yml", ".toml", ""} {
		if path.Ext(base) == ext {
			return true
		}
	}
	return false
}

// isMarkupName: text where HTML comments / hidden CSS are a rendering trick.
func isMarkupName(base string) bool {
	switch strings.ToLower(path.Ext(base)) {
	case ".md", ".mdx", ".mdc", ".markdown", ".html", ".htm", ".rst", ".txt", ".adoc", ".tex":
		return true
	}
	return false
}

var imageExt = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".bmp": true, ".svg": false, ".ico": true, ".tif": true, ".tiff": true, ".avif": true, ".heic": true}
var archiveExt = map[string]bool{".zip": true, ".tar": true, ".gz": true, ".tgz": true, ".xz": true, ".bz2": true, ".zst": true, ".7z": true, ".rar": true, ".whl": true, ".gem": true, ".vsix": true, ".jar": true, ".nupkg": true, ".crx": true, ".xpi": true}
