const express = require("express");

const api = require("./api");

const app = express();
const PORT = Number(process.env.PORT) || 4000;

app.use(express.json());
app.use("/api", api);

app.listen(PORT, () => {
  console.log(`TLS scanner API listening on port ${PORT}`);
});
