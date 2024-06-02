const iframe = document.createElement('iframe');
iframe.src = "https://trusted.com";
iframe.sandbox = "allow-scripts allow-same-origin";
document.body.appendChild(iframe);