import { readFile } from "node:fs/promises";

const html = await readFile(new URL("../access_manager/app/index.html", import.meta.url), "utf8");
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];

if (scripts.length !== 1) {
  throw new Error(`Expected one executable script, found ${scripts.length}`);
}

new Function(scripts[0][1]);

for (const marker of [
  'id="language"',
  'data-tab="people"',
  'data-tab="fingerprints"',
  'data-tab="keypads"',
  'data-tab="doors"',
  'data-tab="logs"',
  'default_action',
  'configureKeypadActionMap',
]) {
  if (!html.includes(marker)) throw new Error(`Missing UI marker: ${marker}`);
}

console.log("UI script and tab structure are valid");
