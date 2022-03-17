# The guardrails-engine-output-schema-validator

This tool allows you to test your output of an engine against our internal schemas.

## Install

Clone:
`git clone guardrailsio/guardrails-engine-output-schema-validator`

Install dependencies
`npm install`

Install into system
`npm link`

## Usage

```shell
guardrails-engine-output-schema-validator --help

  Usage: guardrails-engine-output-schema-validator [options]

  Options:

    -V, --version          output the version number
    -s, --stdin            Read from stdin
    -f, --file [filePath]  Read from file (default: [object Object])
    -h, --help             output usage information
  ```


You can develop your engine locally and then use the stdin to pipe the output directly into the validator.

```shell
 docker run -it --rm -v $(pwd)/test-src/:/opt/mount/ -v $(pwd):/opt/app guardrails-engine-python-bandit | guardrails-engine-output-schema-validator --stdin
envelope  ✅
issue  ✅
issue  ✅
issue  ✅
issue  ✅
issue  ✅

```

In some cases you will run into validation errors. Those look like this:

```js
{ ValidationError: child "rule" fails because ["rule" must be a string]
    at Object.exports.process (/Users/at/src/github.com/guardrailsio/guardrails-engine-output-schema-validator/node_modules/joi/lib/errors.js:196:19)
    at internals.Object._validateWithOptions (/Users/at/src/github.com/guardrailsio/guardrails-engine-output-schema-validator/node_modules/joi/lib/types/any/index.js:675:31)
    at module.exports.internals.Any.root.validate (/Users/at/src/github.com/guardrailsio/guardrails-engine-output-schema-validator/node_modules/joi/lib/index.js:138:23)
    at reportData.output.forEach.lineItem (/Users/at/src/github.com/guardrailsio/guardrails-engine-output-schema-validator/index.js:125:7)
    at Array.forEach (<anonymous>)
    at Object.<anonymous> (/Users/at/src/github.com/guardrailsio/guardrails-engine-output-schema-validator/index.js:117:19)
    at Module._compile (internal/modules/cjs/loader.js:702:30)
    at Object.Module._extensions..js (internal/modules/cjs/loader.js:713:10)
    at Module.load (internal/modules/cjs/loader.js:612:32)
    at tryModuleLoad (internal/modules/cjs/loader.js:551:12)
  isJoi: true,
  name: 'ValidationError',
  details:
   [ { message: '"rule" must be a string',
       path: [Array],
       type: 'string.base',
       context: [Object] } ],
  _object:
   { type: 'issue',
     process: { name: 'eslint', version: '^4.19.1' },
     rule: null,
     description:
      'Parsing error: eval is a reserved word in strict mode\n\n   6 | const bufferNew = require(\'./src/GR0006\')\n   7 | const sqli = require(\'./src/GR0007\')\n>  8 | const eval = require(\'./src/GR0008\')\n     |       ^\n   9 | const exec = require(\'./src/GR0009\')\n  10 |',
     location: { path: '/index.js', positions: [Object] } },
  annotate: [Function] }
  ```

  Usually the validation error is fairly straight forward and gives you enough infos to fix the issue.

