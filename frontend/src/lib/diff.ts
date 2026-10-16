export type DiffKind = "hdr" | "add" | "del" | "ctx";
export interface DiffLine {
  kind: DiffKind;
  text: string;
}

/** Classify a unified diff for display, plus a +/- summary. */
export function parseDiff(diff: string): { lines: DiffLine[]; added: number; removed: number; files: number } {
  const lines: DiffLine[] = [];
  let added = 0;
  let removed = 0;
  let files = 0;
  for (const text of diff.replace(/\n$/, "").split("\n")) {
    let kind: DiffKind = "ctx";
    if (text.startsWith("+++ ")) {
      kind = "hdr";
      files += 1;
    } else if (text.startsWith("--- ") || text.startsWith("@@") || text.startsWith("diff ")) kind = "hdr";
    else if (text.startsWith("+")) {
      kind = "add";
      added += 1;
    } else if (text.startsWith("-")) {
      kind = "del";
      removed += 1;
    }
    lines.push({ kind, text });
  }
  return { lines, added, removed, files };
}

export const GATE_LABELS: Record<string, string> = {
  advisory_present_before: "Scanners saw the CVE before the patch",
  scanners_clear: "Scanners are clear after the patch",
  tests_pass: "The official test suite passes",
  build_diff: "Only expected files changed",
  provenance: "The fix comes from upstream",
};
