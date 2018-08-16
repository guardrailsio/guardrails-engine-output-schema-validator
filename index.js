const Joi = require("joi");

let data = {
  engine: {
    name: "guardrails-engine-javascript",
    version: "1.11.0"
  },
  language: "javascript",
  type: "mixed",
  status: "success",
  executionTime: 3,
  issues: 12,
  errors: null,
  output: [
    {
      type: "issue",
      process: {
        name: "eslint",
        version: "^4.19.1"
      },
      rule: "@guardrails/guardrails/detect-unsafe-regex",
      description: "[GR:0001:stable] Unsafe Regular Expression",
      location: {
        path: "/src/GR0001.js",
        positions: {
          begin: {
            line: 8,
            column: 19
          },
          end: {
            line: 8,
            column: 19
          }
        }
      }
    },
    {
      id: 566,
      updated_at: "2018-05-08T14:27:01.549Z",
      created_at: "2018-02-15T16:45:53.321Z",
      publish_date: "2018-02-15T16:59:37.240Z",
      recommendation: "Update to version 4.2.1, 5.0.3 or later.",
      cvss_vector: "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
      cvss_score: 4,
      module: "hoek",
      version: "5.0.0",
      vulnerable_versions: "<= 4.2.0 || >= 5.0.0 < 5.0.3",
      patched_versions: "> 4.2.0 < 5.0.0 || >= 5.0.3",
      title: "Prototype pollution attack",
      path: ["guardrails-test-javascript@1.0.0", "hoek@5.0.0"],
      advisory: "https://nodesecurity.io/advisories/566",
      type: "advisory",
      process: {
        name: "nsp",
        version: "^3.2.1"
      }
    }
  ]
};
const processSchema = Joi.object().keys({
  name: Joi.string().required(),
  version: Joi.string().required()
});

const dependenciesSchema = Joi.object()
  .keys({
    type: Joi.string().required(),
    cvss_score: Joi.number().required(),
    module: Joi.string().required(),
    version: Joi.string().required(),
    vulnerable_versions: Joi.string().required(),
    process: processSchema
  })
  .options({ stripUnknown: true });

const sourceCodeSchema = Joi.object()
  .keys({
    type: Joi.string().required(),
    process: processSchema,
    rule: Joi.string().required(),
    description: Joi.string().required(),
    // cvss_score: Joi.number().required(),
    location: Joi.object().keys({
      path: Joi.string().required(),
      positions: Joi.object().keys({
        begin: Joi.object()
          .keys({
            line: Joi.number(),
            column: Joi.number().optional()
          })
          .required(),
        end: Joi.object()
          .keys({
            line: Joi.number(),
            column: Joi.number().optional()
          })
          .optional()
      })
    })
  })
  .options({ stripUnknown: true });

const baseSchema = Joi.object().keys({
  engine: Joi.object()
    .keys({
      name: Joi.string().required(),
      version: Joi.string().required()
    })
    .required(),
  language: Joi.string()
    .valid("javascript", "python", "mixed")
    .required(),
  type: Joi.string().required(),
  status: Joi.string()
    .valid("success", "failure")
    .required(),
  executionTime: Joi.number().required(),
  issues: Joi.number().required(),
  errors: [Joi.array(), null],
  output: Joi.array().required()
});

// ========== Validate Outer structure:
Joi.validate(data, baseSchema, (err, value) => {
  if (err) {
    console.log(err);
  } else {
    console.log("------------------> No Error outer");
  }
});

// ========== Validate Output
Joi.validate(data.output[0], sourceCodeSchema, (err, value) => {
  if (err) {
    console.log(err);
  } else {
    console.log("------------------> No Error code");
  }
});

Joi.validate(data.output[1], dependenciesSchema, (err, value) => {
  if (err) {
    console.log(err);
  } else {
    console.log("------------------> No Error");
  }
});
