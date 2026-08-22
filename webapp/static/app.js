/* Progressive enhancement only.
 *
 * The form submits and the report renders with JavaScript disabled. Everything
 * here is convenience: a drag target, a file list, and the score bar width.
 *
 * The score bar cannot use a style attribute in the markup, because the
 * Content-Security-Policy sets style-src 'self' with no 'unsafe-inline' -- so
 * the width is carried in a data attribute and applied here instead. Relaxing
 * the policy to allow one inline style would also allow an injected one.
 */
(function () {
  "use strict";

  function paintScoreBars() {
    document.querySelectorAll(".bar[data-score]").forEach(function (bar) {
      var fill = bar.querySelector("i");
      if (!fill) return;
      var score = Math.max(0, Math.min(100, parseInt(bar.dataset.score, 10) || 0));
      requestAnimationFrame(function () { fill.style.width = score + "%"; });
    });
  }

  function humanSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  }

  function setUpDropzone() {
    var zone = document.getElementById("dropzone");
    var input = document.getElementById("messages");
    var list = document.getElementById("filelist");
    if (!zone || !input || !list) return;

    var maxFiles = parseInt(zone.dataset.maxFiles, 10) || 25;

    function render() {
      var files = Array.prototype.slice.call(input.files || []);
      list.textContent = "";
      list.hidden = files.length === 0;

      files.forEach(function (file, index) {
        var row = document.createElement("li");
        var name = document.createElement("span");
        // textContent, never innerHTML: the filename is attacker-controlled.
        name.textContent = file.name;
        var size = document.createElement("span");
        size.className = "size";
        if (index >= maxFiles) {
          size.classList.add("bad");
          size.textContent = "over the " + maxFiles + "-file limit";
        } else {
          size.textContent = humanSize(file.size);
        }
        row.appendChild(name);
        row.appendChild(size);
        list.appendChild(row);
      });
    }

    input.addEventListener("change", render);

    ["dragenter", "dragover"].forEach(function (type) {
      zone.addEventListener(type, function (event) {
        event.preventDefault();
        zone.classList.add("is-dragging");
      });
    });

    ["dragleave", "drop"].forEach(function (type) {
      zone.addEventListener(type, function (event) {
        event.preventDefault();
        if (type === "dragleave" && zone.contains(event.relatedTarget)) return;
        zone.classList.remove("is-dragging");
      });
    });

    zone.addEventListener("drop", function (event) {
      if (!event.dataTransfer || !event.dataTransfer.files.length) return;
      input.files = event.dataTransfer.files;
      render();
    });
  }

  function guardEmptySubmit() {
    var form = document.getElementById("analyze-form");
    if (!form) return;
    form.addEventListener("submit", function (event) {
      var input = document.getElementById("messages");
      var textarea = form.querySelector("textarea[name=raw_message]");
      var hasFiles = input && input.files && input.files.length > 0;
      var hasText = textarea && textarea.value.trim().length > 0;
      if (!hasFiles && !hasText) {
        event.preventDefault();
        var details = form.querySelector("details.paste");
        if (details) details.open = true;
        if (textarea) textarea.focus();
      }
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    paintScoreBars();
    setUpDropzone();
    guardEmptySubmit();
  });
})();
