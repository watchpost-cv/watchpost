(()=>{
  "use strict";
  let csrf="";
  const q=s=>document.querySelector(s),qa=s=>[...document.querySelectorAll(s)];
  async function api(path,options={}){options.headers={...(options.headers||{}),"Content-Type":"application/json"};if(options.method)options.headers["X-CSRF-Token"]=csrf;const response=await fetch(path,options);if(!response.ok)throw new Error(await response.text());return response.status===204?{}:response.json()}
  async function load(){csrf=(await api("/api/v1/bootstrap")).csrf_token;const data=await api("/api/v1/users");q("[data-users]").innerHTML=data.users.map(user=>`<article class="card"><h3>${user.email}</h3><div class="checks">${["viewer","operator","admin"].map(role=>`<label class="check"><input type="radio" name="role-${user.id}" value="${role}" ${user.role===role?"checked":""}>${role}</label>`).join("")}</div><button data-save="${user.id}">Save user</button><button data-reset="${user.id}">Reset password</button></article>`).join("")}
  qa("[data-tab]").forEach(button=>button.onclick=()=>qa("[data-section]").forEach(section=>section.hidden=section.dataset.section!==button.dataset.tab));
  q("[data-add]").onclick=()=>{const box=q("dialog");const err=box.querySelector(".dialog-error");if(err){err.hidden=true;err.textContent=""}box.showModal()};
  q("form").onsubmit=async event=>{if(event.submitter?.value!=="save")return;event.preventDefault();const f=new FormData(event.currentTarget);if(f.get("password")!==f.get("confirm")){const box=q("dialog");box.querySelector(".dialog-error").textContent="Passwords do not match.";box.querySelector(".dialog-error").hidden=false;return}await api("/api/v1/users",{method:"POST",body:JSON.stringify({username:f.get("username"),email:f.get("email"),password:f.get("password"),role:f.get("role")})});q("dialog").close();load()};
  document.addEventListener("click",async event=>{const card=event.target.closest(".card");if(event.target.dataset.save){await api(`/api/v1/users/${event.target.dataset.save}/role`,{method:"PUT",body:JSON.stringify({role:card.querySelector("input:checked").value})});load()}if(event.target.dataset.reset){const password=prompt("New password (7 characters minimum)");if(password)await api(`/api/v1/users/${event.target.dataset.reset}/reset-password`,{method:"POST",body:JSON.stringify({password})})}});
  load();
})();
