document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const label = button.textContent;
  try {
    await navigator.clipboard.writeText(button.dataset.copy);
    button.textContent = "Copied";
  } catch {
    const code = button.parentElement.querySelector("code");
    window.getSelection().selectAllChildren(code);
    button.textContent = "Selected: press Ctrl+C";
  }
  setTimeout(() => {
    button.textContent = label;
  }, 1500);
});

function showWaiting() {
  const waiting = document.getElementById("main")?.hasAttribute("data-waiting");
  const href = waiting ? "/ui/icon-waiting.svg" : "/ui/icon.svg";
  const icon = document.getElementById("favicon");
  if (icon.getAttribute("href") !== href) icon.setAttribute("href", href);
}
document.addEventListener("DOMContentLoaded", showWaiting);
document.addEventListener("htmx:afterSettle", showWaiting);
