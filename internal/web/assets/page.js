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
