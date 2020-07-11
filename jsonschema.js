const { validator } = require("@exodus/schemasafe");
const fs = require("fs");
const grschema = require("./engines-schema.json");


// pass the external schemas as an option
const validate = validator(grschema, { includeErrors: true, allErrors: true });

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

reportData = readFromStdin();

validate(reportData);
console.log(validate.errors);