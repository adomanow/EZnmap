function updateQueryPreview() {
  const target = document.getElementById('target').value.trim() || '192.168.1.1';
  const mask = document.getElementById('mask').value.trim();
  const query = document.getElementById('query').value;
  const preview = `nmap ${query} ${target}${mask}`;
  document.getElementById('queryPreview').innerText = preview;
}

function startScan(event) {
  event.preventDefault();
  const outputDiv = document.getElementById("output");
  outputDiv.textContent = "";
  outputDiv.style.display = "block";

  const target = document.getElementById("target").value;
  const mask = document.getElementById("mask").value;
  const query = document.getElementById("query").value;

  const formData = new FormData();
  formData.append("target", target);
  formData.append("mask", mask);
  formData.append("query", query);

  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/start-scan", true);

  xhr.onprogress = function () {
    const lines = xhr.responseText.split("\n");
    const latestLine = lines[lines.length - 2]; // Only show the latest line
    outputDiv.textContent = latestLine;
    outputDiv.scrollTop = outputDiv.scrollHeight;
  };

  xhr.onload = function () {
    if (xhr.status === 200) {
      alert("Scan completed successfully!");
      location.reload();
    } else {
      alert("Scan failed: " + xhr.responseText);
    }
  };

  xhr.send(formData);
}

document.addEventListener("DOMContentLoaded", () => {
  const inputs = document.querySelectorAll("#target, #mask, #query");
  inputs.forEach(input => input.addEventListener("input", updateQueryPreview));
  updateQueryPreview();
});
