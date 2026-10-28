// Find backslashes that JavaScript silently DROPS.
//
// In a '...', "..." or `...` literal, "\M" (any character that is not a defined escape) is an
// "identity escape": the backslash vanishes and only "M" survives. That is how this codebase
// shipped T-SQL with 'SoftwareMicrosoftMSSQLServerMSSQLServer' as a registry path, a CHARINDEX
// whose '\' became '', and a 'C:\Program Files\...' with no separators - each one parsed,
// type-checked and passed tests, because the generated text was never compared to intent.
//
// Tokenises properly (comments, strings, template literals with ${} nesting, regex literals,
// which legitimately contain \s \d \w ...) and reports every identity escape inside a string or
// template. Exit code = number of findings, so CI can gate on it.
//
// usage: node scripts/find-identity-escapes.mjs [file ...]   (default: every src/*.ts)
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const VALID = new Set(["n", "r", "t", "b", "f", "v", "0", "x", "u", "'", '"', "\\", "`", "$", "\n", "\r", "\u2028", "\u2029"]);
// After these tokens a '/' starts a regex literal rather than a division.
const REGEX_PRECEDERS = new Set(["(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-", "*", "%", "<", ">", "~", "^", "return", "typeof", "case", "do", "else", "in", "of", "void", "yield", "await", ""]);

function scan(path) {
  const src = readFileSync(path, "utf8");
  const findings = [];
  let i = 0, line = 1, lastSig = "";   // last significant token, for the regex-vs-division decision
  const stack = [];                    // template-literal ${ } nesting: counts open braces per level

  const report = (ch) => {
    const start = src.lastIndexOf("\n", i) + 1, end = src.indexOf("\n", i);
    findings.push({ line, ch, text: src.slice(start, end < 0 ? undefined : end).trim().slice(0, 160) });
  };
  // A quote escaped inside a literal that is NOT delimited by that quote is legal but pointless -
  // and in generated SQL it is how an intended literal backslash disappears: `CHARINDEX('\', x)`
  // inside a template is \' (apostrophe), so the backslash is silently lost. Flag those too.
  const redundant = (delim, nx) =>
    (nx === "'" && delim !== "'") || (nx === '"' && delim !== '"') || (nx === "`" && delim !== "`") || (nx === "$" && delim !== "`");
  const readString = (quote) => {           // i is on the opening quote
    i++;
    while (i < src.length) {
      const c = src[i];
      if (c === "\\") {
        const nx = src[i + 1];
        if (nx === "\n") line++;
        if (nx !== undefined && (!VALID.has(nx) || redundant(quote, nx))) report(nx);
        i += 2; continue;
      }
      if (c === "\n") line++;
      if (c === quote) { i++; return; }
      i++;
    }
  };
  const readTemplate = () => {               // i is just past the opening backtick (or a closing } of ${})
    while (i < src.length) {
      const c = src[i];
      if (c === "\\") {
        const nx = src[i + 1];
        if (nx === "\n") line++;
        if (nx !== undefined && (!VALID.has(nx) || redundant("`", nx))) report(nx);
        i += 2; continue;
      }
      if (c === "\n") line++;
      if (c === "`") { i++; return "end"; }
      if (c === "$" && src[i + 1] === "{") { i += 2; return "expr"; }
      i++;
    }
    return "end";
  };
  const readRegex = () => {                  // i is on the opening '/'
    i++;
    let inClass = false;
    while (i < src.length) {
      const c = src[i];
      if (c === "\\") { i += 2; continue; }
      if (c === "\n") { line++; return; }    // not a regex after all; bail safely
      if (c === "[") inClass = true;
      else if (c === "]") inClass = false;
      else if (c === "/" && !inClass) { i++; while (/[a-z]/i.test(src[i] ?? "")) i++; return; }
      i++;
    }
  };

  while (i < src.length) {
    const c = src[i];
    if (c === "\n") { line++; i++; continue; }
    if (/\s/.test(c)) { i++; continue; }
    if (c === "/" && src[i + 1] === "/") { while (i < src.length && src[i] !== "\n") i++; continue; }
    if (c === "/" && src[i + 1] === "*") {
      i += 2;
      while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) { if (src[i] === "\n") line++; i++; }
      i += 2; continue;
    }
    if (c === "'" || c === '"') { readString(c); lastSig = "str"; continue; }
    if (c === "`") { i++; const r = readTemplate(); if (r === "expr") stack.push(0); lastSig = "str"; continue; }
    if (c === "{" && stack.length) { stack[stack.length - 1]++; i++; lastSig = "{"; continue; }
    if (c === "}" && stack.length) {
      if (stack[stack.length - 1] === 0) {  // closes a ${ } - resume the template
        stack.pop(); i++;
        const r = readTemplate(); if (r === "expr") stack.push(0);
        lastSig = "str"; continue;
      }
      stack[stack.length - 1]--; i++; lastSig = "}"; continue;
    }
    if (c === "/") {
      if (REGEX_PRECEDERS.has(lastSig)) { readRegex(); lastSig = "regex"; continue; }
      i++; lastSig = "/"; continue;
    }
    if (/[A-Za-z_$]/.test(c)) {
      let j = i; while (/[\w$]/.test(src[j] ?? "")) j++;
      lastSig = src.slice(i, j); i = j; continue;
    }
    if (/[0-9]/.test(c)) { while (/[\w.]/.test(src[i] ?? "")) i++; lastSig = "num"; continue; }
    lastSig = c; i++;
  }
  return findings;
}

const files = process.argv.slice(2).length
  ? process.argv.slice(2)
  : readdirSync("src").filter((f) => f.endsWith(".ts")).map((f) => join("src", f));
let total = 0;
for (const f of files) {
  for (const x of scan(f)) {
    total++;
    console.log(`${f}:${x.line}  \\${x.ch === "\n" ? "<newline>" : x.ch}  ${x.text}`);
  }
}
console.log(`\n${total} identity escape(s) - each is a backslash that does not reach the output.`);
process.exit(Math.min(total, 100));
