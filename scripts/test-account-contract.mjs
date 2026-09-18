import fs from "node:fs";

const distHtml = fs.readFileSync("web/dist/index.html", "utf8");
const distJs = fs.readFileSync("web/dist/script.js", "utf8");
const contentHtml = fs.readFileSync("web/content/index.html", "utf8");
function a(cond, msg) { if (!cond) throw new Error(msg); }

// First-run setup: Username, Email, Password, Confirm password (source + served).
for (const [label, html] of [["dist", distHtml], ["content", contentHtml]]) {
  const setup = html.split('<form id="setup">')[1].split("</form>")[0];
  for (const id of ["setup-username", "setup-email", "setup-confirm"]) {
    a(setup.includes('id="' + id + '"'), label + " setup form missing " + id);
  }
  a(setup.includes('name="password"'), label + " setup form missing password");
}
// Additional-account creation (Users page): username, email, password, confirm.
for (const [label, html] of [["dist", distHtml], ["content", contentHtml]]) {
  const create = html.split('<form id="create-user"')[1].split("</form>")[0];
  a(create.includes('name="username"') && create.includes('name="email"') && create.includes('name="password"') && create.includes('id="create-user-confirm"'),
    label + " create-user form missing canonical fields");
}
a(distHtml.includes("Username or email"), "login form must accept username or email");
a(distJs.includes("Passwords do not match."), "frontend must validate password confirmation");

// /manage Add user dialog (served + content copy identical).
for (const [label, file] of [["dist", "web/dist/manage.html"], ["content", "web/content/manage.html"]]) {
  const manage = fs.readFileSync(file, "utf8");
  const dialog = manage.split("<dialog>")[1].split("</dialog>")[0];
  for (const id of ["username", "email", "password", "confirm"]) {
    a(dialog.includes('name="' + id + '"'), label + " manage Add user dialog missing " + id);
  }
  a(/Display name|display/.test(dialog) === false, label + " manage Add user dialog requests a display name");
}
for (const [label, file] of [["dist", "web/dist/manage.js"], ["content", "web/content/manage.js"]]) {
  const mjs = fs.readFileSync(file, "utf8");
  a(mjs.includes("Passwords do not match."), label + " manage frontend must validate password confirmation");
  a(mjs.includes("username:f.get(\"username\")") || mjs.includes("username:f.get('username')"), label + " manage create payload must send username");
}
// Source/generated parity: content and dist copies must be byte-identical.
a(fs.readFileSync("web/dist/manage.html", "utf8") === fs.readFileSync("web/content/manage.html", "utf8"), "manage.html source/generated drift");
a(fs.readFileSync("web/dist/manage.js", "utf8") === fs.readFileSync("web/content/manage.js", "utf8"), "manage.js source/generated drift");

console.log("watchpost account-creation contract: ok");