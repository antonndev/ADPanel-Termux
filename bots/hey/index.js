const http = require("http");

const PORT = 3009;

const server = http.createServer((req, res) => {
  res.writeHead(200, { "Content-Type": "text/plain" });
  res.end("Hello from hey! Running on port " + PORT);
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("Server 'hey' listening on port " + PORT);
});
