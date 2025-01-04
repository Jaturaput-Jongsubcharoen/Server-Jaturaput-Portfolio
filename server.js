const express = require("express");
//const path = require("path");
const cors = require("cors");
const corsOptions = {
    origin: ["http://localhost:5173"],
};

const app = express();

app.use(cors(corsOptions));

//app.use("/favicon.ico", express.static(path.join(__dirname, "public", "favicon.ico")));

app.get("/", (req, res) => {
    res.send("Hello! this is Jaturaput's World!");
});

app.get("/api", (req, res) => {
    res.json({ fruits: ["apple", "orange", "banana"] });
});

app.listen(8080, () => {
    console.log("Server started on port 8080")
});

