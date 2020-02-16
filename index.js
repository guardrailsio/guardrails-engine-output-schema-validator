const Joi = require("joi");
const program = require("commander");
const fs = require("fs");

const pkg = require("./package.json");

/* arguments parsing */
program
  .version(pkg.version)
  .option("-f, --file [filePath]", "Read from file")
  .option("-s, --stdin", "Read from stdin")
  .parse(process.argv);

/* schemas */
const processSchema = Joi.object().keys({
  name: Joi.string().required(),
  version: Joi.string().required()
});

const lineitemSchema = Joi.object().keys({
  type: Joi.string()
    .required()
    .valid("sast", "sca", "secret"),
  ruleId: Joi.string().required(),
  location: Joi.object().keys({
    path: Joi.string()
      .regex(/^(?!\/opt\/mount\/|.\/|\/).*/)
      .required(),
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
  }),
  metadata: Joi.object().required()
});

const envelopeSchema = Joi.object().keys({
  engine: Joi.object()
    .keys({
      name: Joi.string()
      .regex(/guardrails\-engine\-\w+?\-\w+/)
      .required(),
      version: Joi.string().required()
    })
    .required(),
  language: Joi.string()
    .valid("javascript", "python", "ruby", "go", "solidity", "general", "php", "java", "dotnet", "elixir", "c", "rust", "terraform")
    .required(),
  status: Joi.string()
    .valid("success", "failure")
    .required(),
  executionTime: Joi.number().required(),
  issues: Joi.number().required(),
  errors: [Joi.array(), null],
  output: Joi.array().required(),
  rawOutput: [Joi.string().required(), Joi.object().required()],
  process: processSchema.required()
});

const metadataSchemaSAST = Joi.object()
  .keys({
    lineContent: Joi.string().required(),
    confidence: Joi.string().optional(),
    severity: Joi.string().optional(),
    description: Joi.string().optional(),
    title: Joi.string().optional(),
    cweID: Joi.string().optional(),
    references: Joi.array().optional()
  })
  .options({ stripUnknown: true });

const metadataSchemaSCA = Joi.object()
  .keys({
    cweID: Joi.string().optional(),
    cve: Joi.object().optional(),
    title: Joi.string().optional(),
    vulnerableVersions: Joi.string().allow('').optional(),
    patchedVersions: Joi.string().allow('').optional(),
    currentVersion: Joi.string().optional(),
    references: Joi.array().optional(),
    severity: Joi.string().optional(),
    dependencyName: Joi.string().optional()
  })
  .options({ stripUnknown: true });
/* data loading */

function readFromStdin() {
  return readFromFile("/dev/stdin");
}

function readFromFile(filePath) {
  try {
    let data = fs.readFileSync(filePath).toString();
    return JSON.parse(data);
  } catch (err) {
    console.log(err.message);
    process.exit(1);
  }
}
let reportData;

if (program.stdin) {
  reportData = readFromStdin();
} else if (program.file) {
  reportData = readFromFile(program.file);
}

if (!reportData) {
  console.log("No data was supplied to validate. Run `-h` for help.");
  process.exit(1);
}

/* validating the envelope structure */
Joi.validate(reportData, envelopeSchema, (err, value) => {
  if (err) {
    console.log(err);
  } else {
    console.log("envelope  ✅");
  }
});

/* validating the line items */
reportData.output.forEach(lineItem => {
  Joi.validate(lineItem, lineitemSchema, (err, value) => {
    if (err) {
      console.log(err);
    } else {
      console.log(lineItem.type + "  ✅");
    }
  });
  let metadataSchema;
  if (lineItem.type == "sast" || lineItem.type == "secret") {
    metadataSchema = metadataSchemaSAST;
  } else if (lineItem.type == "sca") {
    metadataSchema = metadataSchemaSCA;
  }

  Joi.validate(lineItem.metadata, metadataSchema, (err, value) => {
    if (err) {
      console.log(err);
    } else {
      console.log(lineItem.type + " metadata  ✅");
    }
  });
});
