// Utility functions, e.g., load components (nếu cần include HTML)
function loadComponent(url, elementId) {
    fetch(url)
        .then(response => response.text())
        .then(data => document.getElementById(elementId).innerHTML = data);
}
// Gọi nếu cần: loadComponent('../components/navbar.html', 'navbar');