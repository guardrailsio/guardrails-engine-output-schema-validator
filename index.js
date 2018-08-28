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
    .valid("javascript", "python", "ruby", "mixed")
    .required(),
  type: Joi.string().required(),
  status: Joi.string()
    .valid("success", "failure")
    .required(),
  executionTime: Joi.number().required(),
  issues: Joi.number().required(),
  errors: [Joi.array(), null],
  output: Joi.array().required(),
  rawOutput: Joi.string().required()
});

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

Joi.validate(reportData, baseSchema, (err, value) => {
  if (err) {
    console.log(err);
  } else {
    console.log("envelope  ✅");
  }
});

/* validating the line items */
reportData.output.forEach(lineItem => {
  let schema = Joi.object();
  if (lineItem.type === "issue" || lineItem.type === "sourcecode") {
    schema = sourceCodeSchema;
  } else if (lineItem.type === "advisory") {
    schema = dependenciesSchema;
  } else if (lineItem.type === "secrets") {
  }
  Joi.validate(lineItem, schema, (err, value) => {
    if (err) {
      console.log(err);
    } else {
      console.log(lineItem.type + "  ✅");
    }
  });
});
