/** The GitHub organization that owns the repo and the images. Everything below derives from it. */
export const ORG = "dabao-zero";
/** Where published images live. Pull commands are built from this. */
export const REGISTRY = `ghcr.io/${ORG}`;
export const REPO_URL = `https://github.com/${ORG}/dabao-zero`;
export const SITE_NAME = "dabao-zero";

export function pullCommand(image: string, tag: string): string {
  return `docker pull ${REGISTRY}/${image}:${tag}`;
}
