const express = require("express");
const { ApolloServer, gql } = require("apollo-server-express");
const { MongoClient, ObjectId } = require("mongodb");
const { graphql } = require("graphql");
const { makeExecutableSchema } = require("@graphql-tools/schema");
const fs = require("fs");

env = require("dotenv").config();
const FLAG = process.env.FLAG || "CTF{wiiw}";

const app = express();
app.use(express.json());
const client = new MongoClient("mongodb://mongodb:27017");
let db;

const BLACKLISTED_KEYS = [
  "__schema",
  "schema",
  "type",
  "types",
  "name",
  "schee",
];

const containsTypesKey = (obj) => {
  if (typeof obj !== "object" || obj === null) return null;
  const foundKey = BLACKLISTED_KEYS.find((key) => key in obj);
  if (foundKey) return foundKey;
  for (const value of Object.values(obj)) {
    const result = containsTypesKey(value);
    if (result) return result;
  }
  return null;
};

const vulnerabilities = JSON.parse(fs.readFileSync("vulns.json", "utf8"));

const typeDefs = gql`
  type Query {
    findVulnerabilities(filter: String): [Vulnerability]
    ping: String
    getCommentById(id: ID!): Comment
    getFlag: String
  }

  type Mutation {
    createComment(content: String!): Comment!
    insertFlagAsComment: String!
    insertVulnerability(
      cve: String!
      severity: String!
      affectedSoftware: [String]!
      exploitabilityScore: Float!
      patchAvailable: Boolean!
      disclosureDate: String!
    ): Boolean!
  }

  type Comment {
    id: ID!
    content: String!
    createdAt: String!
  }

  type Vulnerability {
    cve: String
    severity: String
    affectedSoftware: [String]
    exploitabilityScore: Float
    patchAvailable: Boolean
    disclosureDate: String
  }
`;

const resolvers = {
  Query: {
    findVulnerabilities: (parent, { filter }) => {
      if (!filter || filter.trim() === "") return vulnerabilities;
      console.log("filter", filter);
      return vulnerabilities.filter(
        (vuln) =>
          vuln.cve.includes(filter) ||
          vuln.severity.includes(filter) ||
          vuln.affectedSoftware.some((software) => software.includes(filter))
      );
    },
    ping: () => "pong",
    getFlag: () => "try harder",
    getCommentById: async (_, { id }) => {
      if (!ObjectId.isValid(id)) return null;
      const comment = await db
        .collection("comments")
        .findOne({ _id: new ObjectId(id) });
      return comment
        ? {
            id: comment._id.toString(),
            content: comment.content,
            createdAt: comment.createdAt.toISOString(),
          }
        : null;
    },
  },
  Mutation: {
    createComment: async (_, { content }) => {
      const result = await db
        .collection("comments")
        .insertOne({ content, createdAt: new Date() });

      // delete the comment after one minute
      setTimeout(async () => {
        await db
          .collection("comments")
          .deleteOne({ _id: new ObjectId(result.insertedId) });
        console.log(
          `Comment with ID ${result.insertedId} removed after 1 minute`
        );
      }, 60000);

      return {
        id: result.insertedId.toString(),
        content,
        createdAt: new Date().toISOString(),
        message: "This comment will be removed in 1 minute.",
      };
    },
    insertFlagAsComment: async () => {
      await db
        .collection("comments")
        .insertOne({ content: FLAG, createdAt: new Date() });

      setTimeout(async () => {
        await db.collection("comments").deleteOne({ content: FLAG });
        console.log("Flag comment removed after 1 minute");
      }, 60000);

      return "The flag comment has been inserted and will be removed in 1 minute.";
    },
    insertVulnerability: async (
      _,
      {
        cve,
        severity,
        affectedSoftware,
        exploitabilityScore,
        patchAvailable,
        disclosureDate,
      }
    ) => {
      vulnerabilities.push({
        cve,
        severity,
        affectedSoftware,
        exploitabilityScore,
        patchAvailable,
        disclosureDate,
      });
      fs.writeFileSync("vulns.json", JSON.stringify(vulnerabilities, null, 2));
      return true;
    },
  },
};

const schema = makeExecutableSchema({ typeDefs, resolvers });

const performGraphQLQuery = async (query) => {
  const graphqlQuery = `query { findVulnerabilities(filter: "${query}") { cve severity affectedSoftware exploitabilityScore patchAvailable disclosureDate } }`;
  try {
    const response = await graphql({ schema, source: graphqlQuery });
    if (response.errors) {
      return { error: "Something went wrongO42O", details: response.errors };
    }
    const foundKey = containsTypesKey(response.data);
    if (foundKey) {
      return { error: "Danger", details: `You are not allowed to access` };
    }
    return response.data;
  } catch (error) {
    return { error: "Something went wrongO42O", details: error.message };
  }
};
const performGraphQLMutation = async (mutation) => {
  try {
    const response = await graphql({ schema, source: mutation });
    if (response.errors) {
      return { error: "Something went wrongO42O", details: response.errors };
    }
    return response.data;
  } catch (error) {
    return { error: "Something went wrongO42O", details: error.message };
  }
};

app.get("/vulns", async (req, res) => {
  const userInput = req.query.keyword;
  try {
    const result = await performGraphQLQuery(userInput);
    res.json(result);
  } catch (error) {
    res
      .status(500)
      .json({ error: "Something went wrongO42O", details: error.message });
  }
});

app.post("/vulns", async (req, res) => {
  const {
    cve,
    severity,
    affectedSoftware,
    exploitabilityScore,
    patchAvailable,
    disclosureDate,
  } = req.body;

  if (
    !cve ||
    !severity ||
    !Array.isArray(affectedSoftware) ||
    typeof exploitabilityScore !== "number" ||
    typeof patchAvailable !== "boolean" ||
    !disclosureDate
  ) {
    return res.status(400).json({
      error: "Invalid input",
      details: "Please provide all required fields with correct types.",
    });
  }

  const mutation = `mutation { insertVulnerability(cve: "${cve}", severity: "${severity}", affectedSoftware: ${JSON.stringify(
    affectedSoftware
  )}, exploitabilityScore: ${exploitabilityScore}, patchAvailable: ${patchAvailable}, disclosureDate: "${disclosureDate}") }`;

  try {
    const result = await performGraphQLMutation(mutation);
    res.json(result);
  } catch (error) {
    res
      .status(500)
      .json({ error: "Something went wrongO42O", details: error.message });
  }
});

const startServer = async () => {
  await client.connect();
  db = client.db("ctf");

  const server = new ApolloServer({
    schema,
    introspection: false,
    playground: false,
  });

  await server.start();

  // server.applyMiddleware({ app });

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
  });
};

startServer().catch(console.error);