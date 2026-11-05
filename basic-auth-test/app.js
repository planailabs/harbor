// Minimal demo of the cgi-harbor/basic gate: show who's signed in + log out.
// Paths are relative, so this works under whatever folder the app is mounted at
// (e.g. /static/ → /static/cgi-harbor/basic). Cookies ride along same-origin.

const app = document.getElementById("app");

// Use textContent everywhere — never interpolate the username into HTML.
function el(tag, text) {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  return n;
}

function back() {
  return encodeURIComponent(location.href);
}

function renderSignedOut() {
  app.replaceChildren(
    el("p", "Not signed in."),
    Object.assign(el("a", "Sign in"), { href: `cgi-harbor/basic/login?back=${back()}` }),
  );
}

function renderSignedIn(info) {
  const logout = el("button", "Log out");
  logout.addEventListener("click", () => {
    location.href = `cgi-harbor/basic/logout?back=${back()}`;
  });

  const profile = Object.assign(el("a", "View profile"), {
    href: `cgi-harbor/basic/profile?back=${back()}`,
  });
  const profileP = el("p");
  profileP.append(profile);

  const parts = [el("h1", `Signed in as ${info.username}`)];
  if (info.list_name) {
    parts.push(Object.assign(el("p", `Area: ${info.list_name}`), { className: "muted" }));
  }
  parts.push(profileP, logout);
  app.replaceChildren(...parts);
}

async function load() {
  try {
    const res = await fetch("cgi-harbor/basic", { headers: { accept: "application/json" } });
    if (res.status === 401) return renderSignedOut();
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    renderSignedIn(await res.json());
  } catch (e) {
    app.replaceChildren(Object.assign(el("p", `Error: ${e.message}`), { className: "muted" }));
  }
}

load();
