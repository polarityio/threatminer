const request = require('postman-request');
const async = require('async');
const fs = require('fs');
const _ = require('lodash');
const config = require('./config/config');

let Logger;
let requestWithDefaults;
let previousDomainRegexAsString = '';
let previousIpRegexAsString = '';
let domainBlocklistRegex = null;
let ipBlocklistRegex = null;
const IGNORED_IPS = new Set(['127.0.0.1', '255.255.255.255', '0.0.0.0']);

const MAX_DOMAIN_LABEL_LENGTH = 63;
const MAX_PARALLEL_LOOKUPS = 10;

/**
 *
 * @param entities
 * @param options
 * @param cb
 */
function startup(logger) {
  let defaults = {};
  Logger = logger;

  const { cert, key, passphrase, ca, proxy, rejectUnauthorized } = config.request;

  if (typeof cert === 'string' && cert.length > 0) {
    defaults.cert = fs.readFileSync(cert);
  }

  if (typeof key === 'string' && key.length > 0) {
    defaults.key = fs.readFileSync(key);
  }

  if (typeof passphrase === 'string' && passphrase.length > 0) {
    defaults.passphrase = passphrase;
  }

  if (typeof ca === 'string' && ca.length > 0) {
    defaults.ca = fs.readFileSync(ca);
  }

  if (typeof proxy === 'string' && proxy.length > 0) {
    defaults.proxy = proxy;
  }

  if (typeof rejectUnauthorized === 'boolean') {
    defaults.rejectUnauthorized = rejectUnauthorized;
  }

  requestWithDefaults = request.defaults(defaults);
}

function _setupRegexBlocklists(options) {
  if (options.domainBlocklistRegex !== previousDomainRegexAsString && options.domainBlocklistRegex.length === 0) {
    Logger.debug('Removing Domain Blocklist Regex Filtering');
    previousDomainRegexAsString = '';
    domainBlocklistRegex = null;
  } else {
    if (options.domainBlocklistRegex !== previousDomainRegexAsString) {
      previousDomainRegexAsString = options.domainBlocklistRegex;
      Logger.debug({ domainBlocklistRegex: previousDomainRegexAsString }, 'Modifying Domain Blocklist Regex');
      domainBlocklistRegex = new RegExp(options.domainBlocklistRegex, 'i');
    }
  }

  if (options.ipBlocklistRegex !== previousIpRegexAsString && options.ipBlocklistRegex.length === 0) {
    Logger.debug('Removing IP Blocklist Regex Filtering');
    previousIpRegexAsString = '';
    ipBlocklistRegex = null;
  } else {
    if (options.ipBlocklistRegex !== previousIpRegexAsString) {
      previousIpRegexAsString = options.ipBlocklistRegex;
      Logger.debug({ ipBlocklistRegex: previousIpRegexAsString }, 'Modifying IP Blocklist Regex');
      ipBlocklistRegex = new RegExp(options.ipBlocklistRegex, 'i');
    }
  }
}

function _isEntityBlocklisted(entity, { blocklist }) {
  Logger.trace({ blocklist }, 'Blocklist Values');

  const entityIsBlocklisted = _.includes(blocklist, entity.value.toLowerCase());

  const ipIsBlocklisted =
    entity.isIP && !entity.isPrivateIP && ipBlocklistRegex !== null && ipBlocklistRegex.test(entity.value);
  if (ipIsBlocklisted) Logger.debug({ ip: entity.value }, 'Blocked BlockListed IP Lookup');

  const domainIsBlocklisted =
    entity.isDomain && domainBlocklistRegex !== null && domainBlocklistRegex.test(entity.value);
  if (domainIsBlocklisted) Logger.debug({ domain: entity.value }, 'Blocked BlockListed Domain Lookup');

  return entityIsBlocklisted || ipIsBlocklisted || domainIsBlocklisted;
}

function _isInvalidEntity(entity) {
  return entity.isIPv4 && IGNORED_IPS.has(entity.value)
}

function doLookup(entities, options, cb) {
  let lookupResults = [];
  let tasks = [];

  Logger.debug(entities);

  _setupRegexBlocklists(options);

  entities.forEach((entity) => {
    if (!_isInvalidEntity(entity) && !_isEntityBlocklisted(entity, options)) {
      let requestOptions = {
        method: 'GET',
        json: true
      };

      if (entity.isHash) {
        requestOptions.uri = `${options.host}/v2/sample.php`,
        requestOptions.qs = {q: `${entity.value}`, rt: '1'}
      } else if (entity.isDomain) {
        requestOptions.uri = `${options.host}/v2/domain.php`,
        requestOptions.qs = {q: `${entity.value}`, rt: '1'}
      } else if (entity.isIPv4) {
        requestOptions.uri = `${options.host}/v2/host.php`,
        requestOptions.qs = {q: `${entity.value}`, rt: '1'}
      } else {
        return;
      }

      Logger.trace({ uri: requestOptions }, 'Request URI');

      tasks.push(function(done) {
        requestWithDefaults(requestOptions, function(error, res, body) {
          let processedResult = handleRestError(error, entity, res, body);

          if (processedResult.error) {
            done(processedResult);
            return;
          }

          done(null, processedResult);
        });
      });
    }
  });

  async.parallelLimit(tasks, MAX_PARALLEL_LOOKUPS, (err, results) => {
    if (err) {
      Logger.error({ err: err }, 'Error');
      cb(err);
      return;
    }

    results.forEach((result) => {
      if (result.body === null || result.body.length === 0 || result.body.results === null || result.body.results.length === 0) {
        lookupResults.push({
          entity: result.entity,
          data: null
        });
      } else {
        lookupResults.push({
          entity: result.entity,
          data: {
            summary: [],
            details: result.body
          }
        });
      }
    });

    Logger.debug({ lookupResults }, 'Results');
    cb(null, lookupResults);
  });
}

function handleRestError(error, entity, res, body) {
  let result;

  if (error) {
    return {
      error: error,
      detail: 'HTTP Request Error'
    };
  }

  if (res.statusCode === 200) {
    // we got data!
    result = {
      entity: entity,
      body: body
    };
  } else if (res.statusCode === 404) {
    // no result found
    result = {
      entity: entity,
      body: null
    };
  } else if (res.statusCode === 202) {
    // no result found
    result = {
      entity: entity,
      body: null
    };
  } else {
    // unexpected status code
    result = {
      error: body,
      detail: `${body.error}: ${body.message}`
    };
  }
  return result;
}

module.exports = {
  doLookup: doLookup,
  startup: startup
};
