/** Where published images live. Pull commands are built from this. */
export const REGISTRY = "ghcr.io/leejianrong";
export const REPO_URL = "https://github.com/leejianrong/dabao-zero";
export const SITE_NAME = "dabao-zero";

export function pullCommand(image: string, tag: string): string {
  return `docker pull ${REGISTRY}/${image}:${tag}`;
}
