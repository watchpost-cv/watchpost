import fs from "node:fs";

const html = fs.readFileSync("web/dist/index.html", "utf8");
const js = fs.readFileSync("web/dist/script.js", "utf8");
function a(cond, msg) { if (!cond) throw new Error(msg); }

const setup = html.split('<form id="setup">')[1].split("</form>")[0];
for (const id of ["setup-username", "setup-email", "setup-confirm"]) {
  a(setup.includes('id="' + id + '"'), "setup form missing " + id);
}
a(setup.includes('name="password"'), "setup form missing password");
// Additional-account creation (admin Users page) has username, email, password, confirm.
const create = html.split('<form id="create-user"')[1].split("</form>")[0];
a(create.includes('name="username"') && create.includes('name="email"') && create.includes('name="password"') && create.includes('id="create-user-confirm"'),
  "create-user form missing canonical fields");
// Login stays username-or-email.
a(html.includes("Username or email"), "login form must accept username or email");
// Frontend validates confirmation.
a(js.includes("Passwords do not match."), "frontend must validate password confirmation");
console.log("watchpost account-creation contract: ok");